using MacaroonCore.Exceptions;

namespace MacaroonCore.Model
{
	public class MacaroonValidationResult
	{
		public bool IsValid { get; set; }
		public MacaroonValidationException MacaroonValidationException { get; set; }
	}
}
