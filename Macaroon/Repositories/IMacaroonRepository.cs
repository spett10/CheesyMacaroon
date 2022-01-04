using MacaroonCore;
using System.Collections.Generic;

namespace MacaroonTestApi.Repositories
{
	public interface IMacaroonRepository
	{
		string IssueMacaroon(List<string> caveats);

		bool ValidateMacaroon(string serializedMacaroon, List<string> serializedDischargeMacaroons, IPredicateVerifier predicateVerifier);
	}
}
