using System;

namespace MacaroonCore.Exceptions
{
    public class InvalidPredicateException : MacaroonValidationException
    {
        public InvalidPredicateException() : base()
        {

        }

        public InvalidPredicateException(string message, string originId) : base(message, originId)
        {

        }

        public InvalidPredicateException(string message, Exception inner, string originId) : base(message, inner, originId)
        {

        }
    }
}
