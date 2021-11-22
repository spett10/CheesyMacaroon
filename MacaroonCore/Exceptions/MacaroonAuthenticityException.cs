using System;

namespace MacaroonCore.Exceptions
{
	public class MacaroonAuthenticityException : MacaroonValidationException
	{
		public MacaroonAuthenticityException()
		{

		}

		public MacaroonAuthenticityException(string message) : base(message)
		{

		}

		public MacaroonAuthenticityException(string message, Exception inner) : base(message, inner)
		{

		}
	}
}
