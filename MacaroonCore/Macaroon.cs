﻿using MacaroonCore.Exceptions;
using MacaroonCore.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MacaroonCore
{
    public class Macaroon
    {
        public string Location { get; set; }
        public string Id { get; set; }
        public List<Caveat> Caveats { get; set; }
        public byte[] Signature { get; set; }

        [JsonIgnore]
        public bool Discharge { get; set; } 

        public byte[] IdPayload
        {
            get
            {
                return Encode.DefaultByteDecoder(Id);
            }
        }

        private const int IdSizeInBytes = 32;

        [JsonConstructor]
        public Macaroon()
        {

        }

        public string ToJson()
        {
            return JsonSerializer.Serialize(this, new JsonSerializerOptions()
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            });
        }

        public static Macaroon CreateAuthorisingMacaroon(byte[] key, string location = null)
        {
            return new Macaroon(key, GenerateId(), false, location);
        }

        public static Macaroon CreateDischargeMacaroon(byte[] thirdPartyKey, string caveatId, string location, IPredicateVerifier predicateVerifier)
        {
            /* We are given caveatId, which is Enc(ThirdPartyKey, RootKey || Predicate ) */
            /* So to get started we must decrypt it to get the rootkey for the macaroon and the base predicate */

            var payloadRaw = SymmetricCryptography.AesGcmDecrypt(thirdPartyKey, Encode.DefaultByteDecoder(caveatId), Encode.DefaultStringDecoder(location));

            var payload = new DischargePayload(payloadRaw);

            var predicate = Encode.DefaultStringEncoder(payload.Predicate);
            if (!predicateVerifier.Verify(predicate))
            {
                throw new ArgumentException("Predicate could not be verified, cannot create discharge macaroon.");
            }

            return new Macaroon(payload.RootKey, caveatId, true, location);
        }

        private Macaroon(byte[] key, string id, bool isDischarge = false, string location = null)
        {
            Location = location;
            Id = id;
            Caveats = new List<Caveat>();
            Discharge = isDischarge;

            using var hmac = CreateHMAC(key);
            Signature = hmac.ComputeHash(IdPayload);
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

        private static string GenerateId()
        {
            var rng = RandomNumberGenerator.Create();
            var randomBytes = new byte[IdSizeInBytes];
            rng.GetBytes(randomBytes);
            return Encode.DefaultByteEncoder(randomBytes);
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

        /* Hash the signature at the end to prevent further chaining. */
        /* We always expect this to have been done for a discharged macaroon, so noone can continue if we did this, we only expect it at the end. */
        /* So if you somehow obtain this discharge macaroon, you cannot continue it after Finalize since Verify will then fail */
        public Macaroon Finalize()
        {
            Signature = SymmetricCryptography.Hash(Signature);

            return this;
        }

        /// <summary>
        /// The end-user should bind their discharge macaroons to their authorizing macaroon using this function, before sending all macaroons for an access request at a target service. 
        /// 
        /// Otherwise, if you mistakenly send your discharge macaroon to someone, that has a macaroon based on the same root key,
        /// they can freely re-use your discharge macaroons, across any and all macaroos that embed the corresponding third-party caveat identifier
        /// that uses the same root key.
        ///
        /// This would mean they could for example impersonate you, if your 3rd party caveat is the result of you authenticating at a 3rd party IDP.
        /// 
        /// This function prevents that by binding discharge macaroons to the specific authorizing macaroon. 
        /// </summary>
        /// <param name="dischargeMacaroons"></param>
        /// <returns></returns>
        public List<Macaroon> PrepareForRequest(List<Macaroon> dischargeMacaroons)
        {
            var sealedMacaroons = new List<Macaroon>();

            foreach (var dischargeMacaroon in dischargeMacaroons)
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

            return SymmetricCryptography.CanonicalizedHash(elementsToHash);
        }

        public MacaroonValidationResult Validate(List<Macaroon> dischargeMacaroons, IPredicateVerifier predicateVerifier, byte[] key)
        {
            // A root macaroon that is at the top of the macaroon tree will have itself as the authorising macaroon, so this method is just nicer to use in that scenario,
            // rather than exposing the recursive method that takes the authorising macaroon as an argument. 
            return Validate(this, dischargeMacaroons, predicateVerifier, key);
        }

        internal MacaroonValidationResult Validate(Macaroon authorisingMacaroon, List<Macaroon> dischargeMacaroons, IPredicateVerifier predicateVerifier, byte[] key)
        {
            byte[] currentKey;

            var hmac = CreateHMAC(key);
            var rootSignature = hmac.ComputeHash(this.IdPayload);
            currentKey = rootSignature;

            foreach (var caveat in Caveats)
            {
                if (caveat.IsFirstPartyCaveat)
                {
                    if (!predicateVerifier.Verify(caveat.CaveatId)) return new MacaroonValidationResult
                    {
                        IsValid = false,
                        MacaroonValidationException = new InvalidPredicateException("Predicate not verified", this.Id) //Predicate verifier can log as needed if they wish to do so.
                    };
                }
                else
                {
                    var discharger = dischargeMacaroons.FirstOrDefault(x => x.Id.Equals(caveat.CaveatId));

                    if (discharger == null)
                    {
                        return new MacaroonValidationResult
                        {
                            IsValid = false,
                            MacaroonValidationException = new DischargeMacaroonNotFoundException($"Did not find discharge for {nameof(caveat.CaveatId)} {caveat.CaveatId}", this.Id)
                        };
                    }

                    byte[] caveatRootKey;
                    try
                    {
                        // The caveat root key was encrypted with the current signature, and is stored in the verification id (duh). 
                        caveatRootKey = SymmetricCryptography.AesGcmDecrypt(currentKey,
                                                                            Encode.DefaultByteDecoder(caveat.VerificationId),
                                                                            Encode.DefaultStringDecoder(discharger.Location));
                    }
                    catch (Exception)
                    {
                        return new MacaroonValidationResult
                        {
                            IsValid = false,
                            MacaroonValidationException = new MacaroonAuthenticityException("Macaroon not authentic", this.Id) //TODO: does this leak too much? 
                        };
                    }

                    // Recursively verify the discharge macaroon. It itself could have third party caveats, and on and on we go. 
                    // A discharge macaroon itself can have other 3rd party caveats, and then the discharge macaroon should authorize the next level discharge.
                    // The argument is a bit weird in the first call outermost call by the client, since it will always be equal to this. But in recursive calls, this will be a discharge, and auth will be the old this.
                    var innerMacaroonVerificationResult = discharger.Validate(this, dischargeMacaroons, predicateVerifier, caveatRootKey);
                    if (!innerMacaroonVerificationResult.IsValid)
                    {
                        return innerMacaroonVerificationResult;
                    }
                }

                hmac.Key = currentKey;
                currentKey = hmac.ComputeHash(caveat.Payload());
            }

            /* We verify the chain "at once" at the end by checking the final signature is as expected. */
            /* That implies that all preceeding signatures were also correct */

            if (Discharge)
            {
                /* If the current macaroon we are currently verifying is a discharge macaroon, we expect that it was finalized after all predicates, and then bound for the authorizing macaroon. */
                var finalized = SymmetricCryptography.Hash(currentKey);
                currentKey = authorisingMacaroon.BindForRequest(finalized);
            }

            if (!currentKey.TimeConstantCompare(Signature)) return new MacaroonValidationResult
            {
                IsValid = false,
                MacaroonValidationException = new MacaroonAuthenticityException("Macaroon not authentic", this.Id) //TODO: all these errors allow caller to distinguish, do we leak too much info? Can they chew through the MAC this way? 
            };

            hmac.Dispose();

            return new MacaroonValidationResult
            {
                IsValid = true,
                MacaroonValidationException = null
            };
        }

        public string Serialize()
        {
            return Encode.Base64UrlEncode(Encode.DefaultStringDecoder(ToJson()));
        }

        public static Macaroon Deserialize(string b64urlencoded, bool isDischarge)
        {
            try
            {
                var json = Encode.DefaultStringEncoder(Encode.Base64UrlDecode(b64urlencoded));

                var deserialized = JsonSerializer.Deserialize<Macaroon>(json);

                if (string.IsNullOrEmpty(deserialized.Id)) throw new MacaroonDeserializationException($"{nameof(deserialized.Id)} was null or empty");

                if (deserialized.Signature.Length == 0) throw new MacaroonDeserializationException($"{nameof(deserialized.Signature)} was null or empty");

                deserialized.Discharge = isDischarge; // TODO: annoying that caller has to know. Do we actually serialize it currently? Its not covered by signature or part of spec. 

                var caveats = new List<Caveat>();

                //TODO BUG: this doesnt catch our attenuated caveats that we need for discharing? 

                foreach (var caveat in deserialized.Caveats)
                {
                    if (string.IsNullOrEmpty(caveat.VerificationId)) throw new MacaroonDeserializationException($"{nameof(caveat.VerificationId)} was null or empty");

                    if (string.IsNullOrEmpty(caveat.CaveatId)) throw new MacaroonDeserializationException($"{nameof(caveat.CaveatId)} was null or empty");

                    // TODO: some sort of factory pattern to hide this in would probably be nicer, that just returns a caveat for us to put in the list. 
                    if (FirstPartyCaveat.VerificationIdIndicatesFirstPartyCaveat(caveat.VerificationId))
                    {
                        caveats.Add(new FirstPartyCaveat()
                        {
                            CaveatId = caveat.CaveatId,
                            Location = caveat.Location,
                            VerificationId = caveat.VerificationId
                        });
                    }
                    else
                    {
                        caveats.Add(new ThirdPartyCaveat()
                        {
                            CaveatId = caveat.CaveatId,
                            Location = caveat.Location,
                            VerificationId = caveat.VerificationId
                        });
                    }
                }

                deserialized.Caveats = caveats;

                return deserialized;
            }
            catch (Exception e)
            {
                throw new MacaroonDeserializationException($"Failed to deserialize macaroon", e);
            }
        }
    }
}
