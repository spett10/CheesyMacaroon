using System;
using System.Text;

namespace MacaroonCore
{
	public static class Encode
	{
		public delegate byte[] StringDecoder(string str);
		public delegate string StringEncoder(byte[] str);


		public delegate string ByteEncoder(byte[] bytes);
		public delegate byte[] ByteDecoder(string encodedBytesAsString);

		public static StringDecoder DefaultStringDecoder => Encoding.UTF8.GetBytes;
		public static StringEncoder DefaultStringEncoder => Encoding.UTF8.GetString;

		public static ByteEncoder DefaultByteEncoder => Convert.ToBase64String;

		public static ByteDecoder DefaultByteDecoder = Convert.FromBase64String;

		static readonly char[] padding = { '=' };

		public static string Base64UrlEncode(byte[] inArray)
		{
			return Convert.ToBase64String(inArray).TrimEnd(padding).Replace('+', '-').Replace('/', '_');
		}

		public static byte[] Base64UrlDecode(string encoded)
		{
			var replaced = encoded.Replace('_', '/').Replace('-', '+');
			switch(replaced.Length % 4)
			{
				case 2: replaced += "=="; break;
				case 3: replaced += "="; break;
			}
			return Convert.FromBase64String(replaced);
		}
	}
}
