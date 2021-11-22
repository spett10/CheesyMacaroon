using System;

namespace MacaroonCore.Exceptions
{
	public class DischargeMacaroonAuthenticityException : MacaroonValidationException
	{
		public DischargeMacaroonAuthenticityException()
		{

		}

		public DischargeMacaroonAuthenticityException(string message) : base(message)
		{

		}

		public DischargeMacaroonAuthenticityException(string message, Exception exception) : base(message, exception)
		{

		}
	}
}
