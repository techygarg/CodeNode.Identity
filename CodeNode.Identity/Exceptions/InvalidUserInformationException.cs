namespace CodeNode.Identity.Exceptions
{
    public class InvalidUserInformationException : BaseIdentityException
    {
        public InvalidUserInformationException(string error)
            : base(error)
        {
        }

        public InvalidUserInformationException(string error, ErrorCodes errorCode)
            : base(error, errorCode)
        {
        }
    }
}