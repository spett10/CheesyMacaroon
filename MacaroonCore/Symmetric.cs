using System.Linq;
using System.Security.Cryptography;


namespace MacaroonCore
{
	internal class Symmetric
	{
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

		internal static byte[] AesGcmEncrypt(byte[] key, byte[] plaintext)
		{
			var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
			RandomNumberGenerator.Fill(nonce);

			var ciphertext = new byte[plaintext.Length];
			var tag = new byte[AesGcm.TagByteSizes.MaxSize];

			using var aesgcm = new AesGcm(key);
			aesgcm.Encrypt(nonce, plaintext, ciphertext, tag);

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
			var (nonce, ciphertext, tag) = Split(standardFormatCiphertext);
			var plaintext = new byte[ciphertext.Length];

			using var aesgcm = new AesGcm(key);
			aesgcm.Decrypt(nonce, ciphertext, tag, plaintext);

			return plaintext;
		}
	}
}
