using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace MacaroonCore.Dto
{
	public class MacaroonDto
	{
		public string Location { get; set; }
		public string Id { get; set; }
		public List<CaveatDto> Caveats { get; set; }
		public byte[] Signature { get; set; }

		[JsonConstructor]
		public MacaroonDto()
		{

		}
	}
}
