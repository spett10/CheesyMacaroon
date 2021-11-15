using System.Linq;

namespace MacaroonCore
{
	public class ThirdPartyCaveat : Caveat
	{
		private readonly byte[] _verificationId;
		private readonly byte[] _caveatId;

		public ThirdPartyCaveat(string predicate, byte[] caveatRootKey, byte[] embeddingMacaroonSignature, byte[] thirdPartyKey, string location)
		{
			// Use location as AAD for domain separation.
			var locationBytes = Encode.DefaultStringDecoder(location);

			// Encryption of the caveat root key using the current signature from the embedding macaroon. 
			// This enables issuer of macaroon to later decrypt this to obtain caveatRootKey - noone else can obtain it from the macaroon.
			// This caveatRootKey is needed to verify the HMAC on the discharge macaroon for the third party caveat. 
			// Storing it here means the Caveat is self-contained in this regard.
			_verificationId = SymmetricCryptography.AesGcmEncrypt(embeddingMacaroonSignature, 
																  caveatRootKey, 
																  locationBytes);

			VerificationId = Encode.DefaultByteEncoder(_verificationId);

			// Caveat Root key is appended with predicate. We encrypt with the key we have shared with the third party.
			// They can then decrypt and assert the predicate. Then, they will construct the Discharge macaroon signature using the caveat root key.
			// Given the above encryption stored in VerificationId, the issuer can then obtain the rootkey again and use it to verify the discharge macaroon. 
			// The discharge macaroon will have this same identifier as its root element, and that is how we can find the discharge macaroon given a third party caveat.
			_caveatId = SymmetricCryptography.AesGcmEncrypt(thirdPartyKey,
															caveatRootKey.Concat(Encode.DefaultStringDecoder(predicate)).ToArray(),
															locationBytes);  

			CaveatId = Encode.DefaultByteEncoder(_caveatId); 

			Location = location;

			Predicate = ""; //TODO: the predicate is encrypted, so we shoulndt expose it in the clear. 
							// It was verified if we find a discharge macaroon with a proof-of-key signature from the third party.
							// We are not meant to know it? 
		}

		public override byte[] Payload() => _verificationId.Concat(_caveatId).ToArray();
	}
}
