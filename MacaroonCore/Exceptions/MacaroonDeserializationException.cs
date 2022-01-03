using System;
using System.Collections.Generic;
using System.Text;

namespace MacaroonCore.Exceptions
{
	public class MacaroonDeserializationException : MacaroonValidationException
	{
		public MacaroonDeserializationException() : base()
		{

		}

		public MacaroonDeserializationException(string message, string originId) : base(message, originId)
		{

		}

		public MacaroonDeserializationException(string message, Exception inner) : base(message, inner)
		{

		}

		public MacaroonDeserializationException(string message, Exception inner, string originId) : base(message, inner, originId)
		{

		}
	}
}
