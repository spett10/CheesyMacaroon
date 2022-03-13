using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using MacaroonCore;

namespace MacaroonTestApi.Repositories
{
	public class InMemoryMacaroonRepository : IMacaroonRepository
	{
		//TODO: make some singleton wrapper around the key? So we always have the same for testing. 

		private static readonly byte[] _rootKey;

		private readonly Dictionary<string, byte[]> _sharedKeys;

		static InMemoryMacaroonRepository()
		{
			// Just to test it out, we spawn it as singleton, each restart of service would issue a new key and invalidate all macaroons currently issued. So dont do it like this. Unless that is a feature. 
			_rootKey = KeyGen();
		}

		public InMemoryMacaroonRepository()
		{			
			// You wouldnt hardcode keys like this but we are just testing out
			_sharedKeys = new Dictionary<string, byte[]>();
			_sharedKeys.Add("https://localhost", Encode.DefaultStringDecoder("YELLOW SUBMARINEYELLOW SUBMARINE"));
		}

		private static byte[] KeyGen()
		{
			var csprng = RandomNumberGenerator.Create();
			var key = new byte[32];
			csprng.GetBytes(key);
			return key;
		}

		public string IssueMacaroon(List<string> firstPartyCaveats)
		{
			if (firstPartyCaveats.Count < 1) throw new ArgumentException($"{nameof(firstPartyCaveats)} was empty.");

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(_rootKey);

			foreach (var claim in firstPartyCaveats)
			{
				authorisingMacaroon.AddFirstPartyCaveat(new FirstPartyCaveat(claim));
			}

			return authorisingMacaroon.Serialize();
		}

		// Assumes we have a shared key which is found based on location.
		public string ExtendMacaroon(string serializedMacaroon, List<string> firstPartyCaveats, string thirdPartyPredicate, string location)
		{
			if (string.IsNullOrEmpty(thirdPartyPredicate)) throw new ArgumentException($"{nameof(thirdPartyPredicate)} was null or empty.");

			if (!_sharedKeys.ContainsKey(location)) throw new ArgumentException($"No shared key found for {nameof(location)}");

			var macaroon = Macaroon.Deserialize(serializedMacaroon, isDischarge: false);

			foreach (var claim in firstPartyCaveats)
			{
				macaroon.AddFirstPartyCaveat(new FirstPartyCaveat(claim));
			}

			var sharedKey = _sharedKeys[location];
			var dischargeRootKey = KeyGen();
			macaroon.AddThirdPartyCaveat(thirdPartyPredicate, dischargeRootKey, location, sharedKey, out var _);

			return macaroon.Serialize();
		}

		public string IssueDischarge(string serializedMacaroon, string location, List<string> firstPartyCaveats, IPredicateVerifier predicateVerifier)
		{
			if (!_sharedKeys.ContainsKey(location)) throw new ArgumentException($"No shared key found for {nameof(location)}");

			if (string.IsNullOrEmpty(serializedMacaroon)) throw new ArgumentException($"{nameof(serializedMacaroon)} was null or empty.");

			var macaroon = Macaroon.Deserialize(serializedMacaroon, isDischarge: true);

			var locationCaveat = macaroon.Caveats.Where(c => c.Location != null && c.Location.Equals(location)).FirstOrDefault();

			if (locationCaveat == null) throw new ArgumentException($"No caveat found for location {location}.");

			var sharedKey = _sharedKeys[location];
			var dischargeMacaroon = Macaroon.CreateDischargeMacaroon(sharedKey, locationCaveat.CaveatId, location, predicateVerifier);

			foreach(var caveat in firstPartyCaveats)
			{
				dischargeMacaroon.AddFirstPartyCaveat(new FirstPartyCaveat(caveat));
			}

			dischargeMacaroon.Finalize();

			return dischargeMacaroon.Serialize();
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
