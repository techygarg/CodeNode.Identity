namespace CodeNode.Identity.Exceptions
{
    public class UserNotExistException : BaseIdentityException
    {
        public UserNotExistException(string error)
            : base(error)
        {
        }

        public UserNotExistException(string error, ErrorCodes errorCode)
            : base(error, errorCode)
        {
        }
    }
}