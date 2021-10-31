﻿using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System;

namespace MacaroonCore
{
	public class Macaroon
	{
		public string Location { get; set; }
		public string Id { get; set; }
		public List<Caveat> Caveats { get; set; }
		public byte[] Signature { get; set; }

		public bool Discharge { get; set; }


		public static Macaroon CreateAuthorisingMacaroon(byte[] key, string id, string location = null)
		{
			return new Macaroon(key, id, false, location);
		}

		public static Macaroon CreateDischargeMacaroon(byte[] thirdPartyKey, string caveatId, string location, IPredicateVerifier predicateVerifier)
		{
			/* We are given caveatId, which is Enc(ThirdPartyKey, RootKey || Predicate ) */
			/* So to get started we must decrypt it to get the rootkey for the macaroon and the base predicate */

			var payload = SymmetricCryptography.AesGcmDecrypt(thirdPartyKey, Encode.DefaultByteDecoder(caveatId));

			/* Payload is RN || predicate, so we remove the first part since its supposed to be a certain length. TODO: make this not implicit */
			var rootKey = payload.Take(32).ToArray();

			var predicate = Encode.DefaultStringEncoder(payload.Skip(32).ToArray());
			if(!predicateVerifier.Verify(predicate))
			{
				throw new ArgumentException("Predicate could not be verified, cannot create discharge macaroon.");
			}

			return new Macaroon(rootKey, caveatId, true, location);
		}

		private Macaroon(byte[] key, string id, bool isDischarge = false, string location = null)
		{
			Location = location;
			Id = id;
			Caveats = new List<Caveat>();

			using var hmac = CreateHMAC(key);
			Signature = hmac.ComputeHash(IdPayload);

			Discharge = isDischarge;
		}

		public byte[] IdPayload { 
			get 
			{ 
				if (Discharge) 
				{
					// TODO: cant we always just decode from b64 instead of using GUIDS as identifiers? Then we dont need branching here. 
					return Encode.DefaultByteDecoder(Id);
				} 
				else 
					return Encode.DefaultStringDecoder(Id); 
			}
		}  

		private Macaroon AddCaveatHelper(Caveat caveat)
		{
			Caveats.Add(caveat);

			using (var hmac = CreateHMAC(Signature))
			{
				Signature = hmac.ComputeHash(caveat.Payload());
			}

			return this;
		}

		private HMAC CreateHMAC(byte[] key)
		{
			return new HMACSHA256(key);
		}

		private bool IsFirstPartyCaveat(Caveat caveat)
		{
			return caveat.VerificationId.Equals(FirstPartyCaveat.FirstPartyCaveatIndicator); //TODO: this can probably be made better with polymorphism or something. 
		}

		public Macaroon AddFirstPartyCaveat(FirstPartyCaveat caveat)
		{
			AddCaveatHelper(caveat);
			return this;
		}

		public Macaroon AddThirdPartyCaveat(string predicate, byte[] caveatRootKey, string location, byte[] thirdPartyKey, out string caveatId)
		{
			var thirdPartyCaveat = new ThirdPartyCaveat(predicate, caveatRootKey, Signature, thirdPartyKey, location);
			AddCaveatHelper(thirdPartyCaveat);
			caveatId = thirdPartyCaveat.CaveatId;
			return this;
		}

		/* Hash the signature at the end to prevent further chaining */
		public Macaroon Finalize()
		{
			this.Signature = SymmetricCryptography.Hash(this.Signature);

			return this;
		}

		public List<Macaroon> PrepareForRequest(List<Macaroon> dischargeMacaroons)
		{
			/* We must bind each discharge macaroon to the authorizing macaroon. 
			 * Otherwise, if you mistakenly send your discharge macaroon to someone, that has a macaroon based on the same root key,
			 * they can freely re-use your discharge macaroons, across any and all macaroos that embed the corresponding third-party caveat identifier
			 * that uses the same root key. 
			 * 
			 * This would mean they could for example impersonate you, if your 3rd party caveat is the result of you authenticating at a 3rd party IDP.
			 *  
			 * */

			var sealedMacaroons = new List<Macaroon>();

			foreach(var dischargeMacaroon in dischargeMacaroons)
			{
				var newSignature = this.BindForRequest(dischargeMacaroon);
				dischargeMacaroon.Signature = newSignature;
				sealedMacaroons.Add(dischargeMacaroon);
			}

			return sealedMacaroons;
		}

		private byte[] BindForRequest(Macaroon dischargeMacaroon)
		{
			return BindForRequest(dischargeMacaroon.Signature);
		}

		private byte[] BindForRequest(byte[] signature)
		{
			/* We have chosen to hash together each individual signature */
			var elementsToHash = new List<byte[]>
			{
				this.Signature,
				signature
			};

			return SymmetricCryptography.Hash(elementsToHash);
		}


		public bool Verify(Macaroon authorisingMacaroon, List<Macaroon> dischargeMacaroons, IPredicateVerifier predicateVerifier, byte[] key)
		{
			var hmac = CreateHMAC(key);
			var rootSignature = hmac.ComputeHash(this.IdPayload);
			var currentKey = rootSignature;

			foreach(var caveat in Caveats)
			{
				if (IsFirstPartyCaveat(caveat))
				{
					if (!predicateVerifier.Verify(caveat.Predicate)) return false;
				}
				else
				{
					var discharger = dischargeMacaroons.FirstOrDefault(x => x.Id.Equals(caveat.CaveatId));

					/* TODO: Should we throw exceptions instead of true/false? Debugging is hard when you dont know that, e.g., you didnt find the discharge macaroon */
					if (discharger == null) 
					{
						return false;
					}
					
					// The caveat root key was encrypted with the current signature, and is stored in the verification id (duh). 
					var caveatRootKey = SymmetricCryptography.AesGcmDecrypt(Signature, Encode.DefaultByteDecoder(caveat.VerificationId));

					// Recursively verify the discharge macaroon. It itself could have third party caveats, and on and on we go. 
					//TODO: what authorizing macaroon do we send in below. Us or the one above? 
					//CURRENT SOLUTION: It seems that we always use the root auth macaroon in recursive calls, TM. And when calling outermost, TM.Verify(TM.. 
					if (!discharger.Verify(authorisingMacaroon, dischargeMacaroons, predicateVerifier, caveatRootKey)) 
					{ 
						return false; 
					}

				}			    
	
				hmac.Key = currentKey;
				currentKey = hmac.ComputeHash(caveat.Payload());
			}

			/* We verify the chain "at once" at the end by checking the final signature is as expected. */
			/* That implies that all preceeding signatures were also correct */

			if (Discharge)
			{
				/* If the current macaroon we are currently verifying is a discharge macaroon, we expect its signature to be bound to authorizing macaroon like so */
				currentKey = authorisingMacaroon.BindForRequest(currentKey);
			}

			if (!currentKey.TimeConstantCompare(Signature)) return false;

			hmac.Dispose();

			return true;
		}


	}
}
