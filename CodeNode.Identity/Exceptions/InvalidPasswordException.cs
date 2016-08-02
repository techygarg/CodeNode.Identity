namespace CodeNode.Identity.Exceptions
{
    public class InvalidPasswordException : BaseIdentityException
    {
        public InvalidPasswordException(string error)
            : base(error)
        {
        }

        public InvalidPasswordException(string error, ErrorCodes errorCode)
            : base(error, errorCode)
        {
        }
    }
}