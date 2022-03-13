using System.Text.Json.Serialization;

namespace MacaroonCore.Dto
{
	public class CaveatDto
	{
		public string Location { get; set; }
		public string CaveatId { get; set; }
		public string VerificationId { get; set; }

		[JsonConstructor]
		public CaveatDto()
		{

		}
	}
}
