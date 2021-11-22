using System;
namespace MacaroonCore.Exceptions
{
	public class MacaroonValidationException : Exception
	{
		public MacaroonValidationException()
		{

		}

		public MacaroonValidationException(string message) : base(message)
		{

		}

		public MacaroonValidationException(string message, Exception inner) : base(message, inner)
		{

		}

	}
}
