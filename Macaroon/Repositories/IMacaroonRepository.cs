using MacaroonCore;
using System.Collections.Generic;

namespace MacaroonTestApi.Repositories
{
	public interface IMacaroonRepository
	{
		string IssueMacaroon(List<string> caveats);

		bool ValidateMacaroon(string serializedMacaroon, List<string> serializedDischargeMacaroons, IPredicateVerifier predicateVerifier);

		string ExtendMacaroon(string serializedMacaroon, List<string> firstPartyCaveats, string thirdPartyPredicate, string location);

		string IssueDischarge(string caveatid, string location, List<string> firstPartyCaveats, IPredicateVerifier predicateVerifier);
	}
}
