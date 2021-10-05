using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace MacaroonCore
{
	public class ThirdPartyCaveat : Caveat
	{
		public ThirdPartyCaveat(string predicate, byte[] caveatRootKey, byte[] embeddingMacaroonSignature, byte[] thirdPartyKey, string location)
		{
			// Encryption of the caveat root key using the current signature from the embedding macaroon. 
			// This enables issuer of macaroon to later decrypt this to obtain caveatRootKey. 
			// This caveatRootKey is needed to start chaining the discharge macaroon we will need to verify the ThirdPartyCaveat. 
			VerificationId = Encode.DefaultByteEncoder(AesGcm(embeddingMacaroonSignature, 
															  caveatRootKey)); 

			// Root key is appended with predicate. We encrypt with the key we have shared with the third party.
			// They can then decrypt and assert the predicate. 
			CaveatId = Encode.DefaultByteEncoder(AesGcm(thirdPartyKey, 
														caveatRootKey.Concat(Encode.DefaultStringDecoder(predicate)).ToArray())); 



			Location = location;
		}

		public override byte[] Payload()
		{
			throw new NotImplementedException();
		}

		private byte[] AesGcm(byte[] key, byte[] plaintext)
		{
			var nonce = new byte[System.Security.Cryptography.AesGcm.NonceByteSizes.MaxSize];
			RandomNumberGenerator.Fill(nonce);

			var ciphertext = new byte[plaintext.Length];
			var tag = new byte[System.Security.Cryptography.AesGcm.TagByteSizes.MaxSize];

			using var aesgcm = new AesGcm(key);
			aesgcm.Encrypt(nonce, plaintext, ciphertext, tag);

			var standardFormat = nonce.Concat(ciphertext).Concat(tag).ToArray();
			return standardFormat;		
		}
	}
}
