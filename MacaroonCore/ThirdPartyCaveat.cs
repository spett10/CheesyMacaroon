﻿using System.Linq;

namespace MacaroonCore
{
    public class ThirdPartyCaveat : Caveat
    {
        internal ThirdPartyCaveat()
        {

        }

        public ThirdPartyCaveat(string predicate, byte[] caveatRootKey, byte[] embeddingMacaroonSignature, byte[] thirdPartyKey, string location)
        {
            // Use location as AAD for domain separation.
            var locationBytes = Encode.DefaultStringDecoder(location);

            // Encryption of the caveat root key using the current signature from the embedding macaroon. 
            // This enables issuer of macaroon to later decrypt this to obtain caveatRootKey - noone else can obtain it from the macaroon.
            // This caveatRootKey is needed to verify the HMAC on the discharge macaroon for the third party caveat. 
            // Storing it here means the Caveat is self-contained in this regard.
            var verificationIdBytes = SymmetricCryptography.AesGcmEncrypt(embeddingMacaroonSignature,
                                                                  caveatRootKey,
                                                                  locationBytes);

            VerificationId = Encode.DefaultByteEncoder(verificationIdBytes);

            // Caveat Root key is appended with predicate. We encrypt with the key we have shared with the third party.
            // They can then decrypt and assert the predicate. Then, they will construct the Discharge macaroon signature using the caveat root key.
            // Given the above encryption stored in VerificationId, the issuer can then obtain the rootkey again and use it to verify the discharge macaroon. 
            // The discharge macaroon will have this same identifier as its root element, and that is how we can find the discharge macaroon given a third party caveat.
            var caveatIdBytes = SymmetricCryptography.AesGcmEncrypt(thirdPartyKey,
                                                            caveatRootKey.Concat(Encode.DefaultStringDecoder(predicate)).ToArray(),
                                                            locationBytes);

            CaveatId = Encode.DefaultByteEncoder(caveatIdBytes);

            Location = location;
        }

        public override bool IsFirstPartyCaveat { get { return false; } }

        public override byte[] Payload() => 
                                Encode.DefaultByteDecoder(VerificationId)
                                .Concat(Encode.DefaultByteDecoder(CaveatId))
                                .ToArray();
    }
}
