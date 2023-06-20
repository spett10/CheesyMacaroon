using System;

namespace MacaroonCore.Exceptions
{
    public class DischargeMacaroonNotFoundException : MacaroonValidationException
    {
        public DischargeMacaroonNotFoundException() : base()
        {

        }

        public DischargeMacaroonNotFoundException(string message, string originId) : base(message, originId)
        {

        }

        public DischargeMacaroonNotFoundException(string message, Exception inner, string originId) : base(message, inner, originId)
        {

        }
    }
}
