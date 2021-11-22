using System;

namespace MacaroonCore.Exceptions
{
	public class InvalidPredicateException : MacaroonValidationException
	{
		public InvalidPredicateException()
		{

		}

		public InvalidPredicateException(string message) : base(message)
		{

		}

		public InvalidPredicateException(string message, Exception inner) : base(message, inner)
		{

		}
	}
}
