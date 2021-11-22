using System;

namespace MacaroonCore.Exceptions
{
	public class DischargeMacaroonNotFoundException : MacaroonValidationException
	{
		public DischargeMacaroonNotFoundException()
		{

		}

		public DischargeMacaroonNotFoundException(string message) : base(message)
		{

		}

		public DischargeMacaroonNotFoundException(string message, Exception inner) : base(message, inner)
		{

		}	
	}
}
