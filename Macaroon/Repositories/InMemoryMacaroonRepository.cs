using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using MacaroonCore;

namespace MacaroonTestApi.Repositories
{
	public class InMemoryMacaroonRepository : IMacaroonRepository
	{
		private readonly byte[] _rootKey;

		public InMemoryMacaroonRepository()
		{
			// Just to test it out, we spawn it as singleton, each restart of service would issue a new key and invalidate all macaroons currently issued. So dont do it like this. Unless that is a feature. 
			var csprng = RandomNumberGenerator.Create();
			_rootKey = new byte[32];
			csprng.GetBytes(_rootKey);
		}

		public string IssueMacaroon(List<string> caveats)
		{
			if (caveats.Count < 1) throw new ArgumentException($"{nameof(caveats)} was empty.");

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(_rootKey);

			foreach(var claim in caveats)
			{
				authorisingMacaroon.AddFirstPartyCaveat(new FirstPartyCaveat(claim));
			}

			return authorisingMacaroon.Serialize();
		}

		public bool ValidateMacaroon(string serializedMacaroon, List<string> serializedDischargeMacaroons, IPredicateVerifier predicateVerifier)
		{
			try
			{
				var macaroon = Macaroon.Deserialize(serializedMacaroon, isDischarge: false);

				var discharges = new List<Macaroon>();

				foreach(var serializedDischarge in serializedDischargeMacaroons)
				{
					var discharge = Macaroon.Deserialize(serializedDischarge, isDischarge: true);
					discharges.Add(discharge);
				}

				var validationResult = macaroon.Validate(discharges, predicateVerifier, _rootKey);

				// Log exception?
				//TODO

				return validationResult.IsValid;
			}
			catch (Exception)
			{
				// TODO: logger 
				return false;
			}
		}
	}
}
