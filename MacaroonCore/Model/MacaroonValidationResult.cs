using System;

namespace MacaroonCore.Model
{
	public class MacaroonValidationResult
	{
		public bool IsValid { get; set; }
		public Exception MacaroonValidationException { get; set; }
	}
}
