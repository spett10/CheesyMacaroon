using System;
namespace MacaroonCore.Exceptions
{
	public class MacaroonValidationException : Exception
	{
		public string OriginId { get; internal set; }

		public MacaroonValidationException()
		{
			OriginId = "";
		}

		public MacaroonValidationException(string message, Exception inner) : base(message, inner)
		{
			OriginId = "";
		}

		public MacaroonValidationException(string message, string originId) : base(message)
		{
			OriginId = originId;
		}

		public MacaroonValidationException(string message, Exception inner, string originId) : base(message, inner)
		{
			OriginId = originId;
		}

	}
}
