using System.Collections.Generic;
using System.Linq;

namespace MacaroonCore
{
	public class FirstPartyCaveat : Caveat
	{
		public FirstPartyCaveat(string predicate, string location = null)
		{
			VerificationId = "0";

			Location = location;

			//First class caveats has the predicate as their Id.
			CaveatId = predicate;
			Predicates = new List<string>() { CaveatId };
		}

		public override byte[] Payload() =>
								Encode.DefaultDecoder(CaveatId)
								.Concat(Encode.DefaultDecoder(VerificationId))
								.ToArray();
	}
}
