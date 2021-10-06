using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace MacaroonCore
{
	public class Macaroon
	{
		public string Location { get; set; }
		public string Id { get; set; }
		public List<Caveat> Caveats { get; set; }
		public byte[] Signature { get; set; }

		private Macaroon()
		{

		}

		public Macaroon(byte[] key, string id, string location = null)
		{
			Location = location;
			Id = id;
			Caveats = new List<Caveat>();

			using var hmac = CreateHMAC(key);
			Signature = hmac.ComputeHash(IdPayload);
		}

		public byte[] IdPayload => Encode.DefaultStringDecoder(Id); //TODO: this should be consistent with discharge macaroons - which are set to use b64(bytes of Enc(Ka, rootkey || predicate); 

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

		public Macaroon AddThirdPartyCaveat(byte[] caveatRootKey, string location, string predicate, byte[] thirdPartyKey)
		{
			var thirdPartyCaveat = new ThirdPartyCaveat(predicate, caveatRootKey, Signature, thirdPartyKey, location);
			AddCaveatHelper(thirdPartyCaveat);
			return this;
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
					var caveatRootKey = Symmetric.AesGcmDecrypt(Signature, Encode.DefaultByteDecoder(caveat.VerificationId));

					// Recursively verify the discharge macaroon. It itself could have third party caveats, and on and on we go. 
					//TODO: what authorizing macaroon do we send in below. Us or the one above? 
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
			if (!currentKey.TimeConstantCompare(Signature)) return false;

			//TODO: we need the bind-for-request feature. The signature we expect should be Hash( DischargeMacaroon.Signature || AuthorisingMacaroo.Signature) to bind them together. 

			hmac.Dispose();

			return true;
		}


	}
}
