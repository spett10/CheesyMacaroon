using System.Linq;

namespace MacaroonCore
{
	public class FirstPartyCaveat : Caveat
	{
		public static string FirstPartyCaveatIndicator = "0";

		internal FirstPartyCaveat()
		{

		}

		public FirstPartyCaveat(string predicate, string location = null)
		{
			VerificationId = FirstPartyCaveatIndicator;

			Location = location;

			//First class caveats has the predicate as their Id.
			CaveatId = predicate;
		}

		public override bool IsFirstPartyCaveat { get { return true; } }
		
		public override byte[] Payload() =>
								Encode.DefaultStringDecoder(CaveatId)
								.Concat(Encode.DefaultStringDecoder(VerificationId))
								.ToArray();
	}
}
