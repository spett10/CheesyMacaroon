using System;
using System.Text;

namespace MacaroonCore
{
	public static class Encode
	{
		public delegate byte[] StringDecoder(string str);

		public delegate string ByteEncoder(byte[] bytes);

		public static StringDecoder DefaultStringDecoder => Encoding.UTF8.GetBytes; //TODO: allow this to be set?

		public static ByteEncoder DefaultByteEncoder => Convert.ToBase64String;
	}
}
