using System.Collections.Generic;

namespace MacaroonCore
{
	public class FirstPartyCaveat : Caveat
	{
		public FirstPartyCaveat(string predicate, string location = null)
		{
			VerificationId = "0";

			Location = location;
			CaveatId = predicate; //First class caveats has the predicate as their Id. 

			Predicates = new List<string>() { CaveatId };
		}
	}
}
