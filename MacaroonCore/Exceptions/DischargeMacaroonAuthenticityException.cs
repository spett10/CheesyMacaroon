using System;

namespace MacaroonCore.Exceptions
{
	public class DischargeMacaroonAuthenticityException : MacaroonValidationException
	{
		public DischargeMacaroonAuthenticityException() : base()
		{

		}

		public DischargeMacaroonAuthenticityException(string message, string originId) : base(message, originId)
		{
			
		}

		public DischargeMacaroonAuthenticityException(string message, Exception exception, string originId) : base(message, exception, originId)
		{

		}
	}
}
