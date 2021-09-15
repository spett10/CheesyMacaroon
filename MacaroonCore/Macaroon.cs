using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace MacaroonCore
{
	public class Macaroon
	{
		public string Location { get; set; }
		public string Id { get; set; }
		public List<FirstPartyCaveat> Caveats { get; set; } //TODO: find some design pattern so we can have this as just Caveat and dynamic dispatch on first party or third party. 
		public byte[] Signature { get; set; }

		private Macaroon()
		{

		}

		public Macaroon(byte[] key, string id, string location = null)
		{
			Location = location;
			Id = id;
			Caveats = new List<FirstPartyCaveat>();

			using var hmac = CreateHMAC(key);
			var data = Encoding.UTF8.GetBytes(Id);
			Signature = hmac.ComputeHash(data);
		}

		public byte[] IdPayload => Encoding.UTF8.GetBytes(Id);

		private Macaroon Copy()
		{
			return new Macaroon()
			{
				Location = this.Location,
				Id = this.Id,
				Caveats = this.Caveats,
				Signature = this.Signature
			};
		}

		private Macaroon AddCaveatHelper(FirstPartyCaveat caveat)
		{
			Caveats.Add(caveat);

			using (var hmac = CreateHMAC(Signature))
			{
				Signature = hmac.ComputeHash(caveat.Payload);
			}

			return this;
		}

		private HMAC CreateHMAC(byte[] key)
		{
			return new HMACSHA256(key);
		}

		public Macaroon AddCaveat(FirstPartyCaveat caveat)
		{
			return Copy().AddCaveatHelper(caveat);
		}

		public bool Verify(Macaroon authorisingMacaroon, List<Macaroon> dischargeMacaroon, IPredicateVerifier predicateVerifier, byte[] key)
		{
			using var rootHmac = CreateHMAC(key);
			var rootSignature = rootHmac.ComputeHash(authorisingMacaroon.IdPayload);
			var currentKey = key;

			foreach(var caveat in Caveats)
			{
				foreach(var predicate in caveat.Predicates)
				{
					if (!predicateVerifier.Verify(predicate)) return false;
				}

				rootHmac.Key = currentKey;
				currentKey = rootHmac.ComputeHash(caveat.Payload);
			}

			if (!currentKey.TimeConstantCompare(Signature)) return false;

			return true;
		}
	}
}
