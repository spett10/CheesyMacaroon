using System;

namespace MacaroonCore.Exceptions
{
    public class MacaroonAuthenticityException : MacaroonValidationException
    {
        public MacaroonAuthenticityException() : base()
        {

        }

        public MacaroonAuthenticityException(string message, string originId) : base(message, originId)
        {

        }

        public MacaroonAuthenticityException(string message, Exception inner, string originId) : base(message, inner, originId)
        {

        }
    }
}
