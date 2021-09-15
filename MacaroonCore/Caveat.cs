using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace MacaroonCore
{
	public abstract class Caveat
	{
		public string Location { get; set; }
		public string CaveatId { get; set; }
		public string VerificationId { get; set; }

		public byte[] Payload =>
		
			Encoding.UTF8.GetBytes(CaveatId)
								.Concat(Encoding.UTF8.GetBytes(VerificationId))
								.ToArray();
		

		public List<string> Predicates { get; set; }
	}
}
