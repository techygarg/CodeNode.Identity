namespace CodeNode.Identity.Exceptions
{
    public class IdentityException : BaseIdentityException
    {
        public IdentityException(string error)
            : base(error)
        {
        }

        public IdentityException(string error, ErrorCodes errorCode)
            : base(error, errorCode)
        {
        }
    }
}