using System.Text;

namespace MacaroonCore
{
	public static class Encode
	{
		public delegate byte[] StringDecoder(string str);

		public static StringDecoder DefaultDecoder => Encoding.UTF8.GetBytes; //TODO: allow this to be set?
	}
}
