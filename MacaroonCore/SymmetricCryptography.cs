using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace MacaroonCore
{
	internal class SymmetricCryptography
	{
		public static int AesKeySizeInBytes = 32;
		private static byte[] Join(byte[] nonce, byte[] ciphertext, byte[] tag)
		{
			var standardFormat = nonce.Concat(ciphertext).Concat(tag).ToArray();
			return standardFormat;
		}

		private static (byte[], byte[], byte[]) Split(byte[] standardFormat)
		{
			var nonce = standardFormat.Take(AesGcm.NonceByteSizes.MaxSize).ToArray();
			var tag = standardFormat.Reverse().Take(AesGcm.TagByteSizes.MaxSize).Reverse().ToArray(); //Yikes the performance. 

			var ciphertextLength = standardFormat.Length - nonce.Length - tag.Length;
			var ciphertext = standardFormat.Skip(nonce.Length).Take(ciphertextLength).ToArray();

			return (nonce, ciphertext, tag);
		}

		internal static byte[] Hash(List<byte[]> elements)
		{
			var fullInput = elements.SelectMany(x => x).ToArray();

			using var sha256 = SHA256.Create();
			return sha256.ComputeHash(fullInput);
		}

		internal static byte[] Hash(byte[] data)
		{
			using var sha256 = SHA256.Create();
			return sha256.ComputeHash(data);
		}

		internal static byte[] AesGcmEncrypt(byte[] key, byte[] plaintext)
		{
			return AesGcmEncrypt(key, plaintext, null);
		}

		internal static byte[] AesGcmEncrypt(byte[] key, byte[] plaintext, byte[] aad)
		{

			var nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; // Keys are used once, so nonce is not something we need to keep track of. 
			RandomNumberGenerator.Fill(nonce);

			var ciphertext = new byte[plaintext.Length];
			var tag = new byte[AesGcm.TagByteSizes.MaxSize];

			using var aesgcm = new AesGcm(key);
			aesgcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

			return Join(nonce, ciphertext, tag);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="key">Symmetric Key. </param>
		/// <param name="standardFormatCiphertext"> nonce || ciphertext || tag, where nonce and tag are assumed to be max size. </param>
		/// <returns></returns>
		internal static byte[] AesGcmDecrypt(byte[] key, byte[] standardFormatCiphertext)
		{
			return AesGcmDecrypt(key, standardFormatCiphertext, null);
		}

		internal static byte[] AesGcmDecrypt(byte[] key, byte[] standardFormatCiphertext, byte[] aad)
		{
			var (nonce, ciphertext, tag) = Split(standardFormatCiphertext);
			var plaintext = new byte[ciphertext.Length];

			using var aesgcm = new AesGcm(key);
			aesgcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);

			return plaintext;
		}
	}
}
