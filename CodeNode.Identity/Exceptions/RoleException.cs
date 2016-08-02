namespace CodeNode.Identity.Exceptions
{
    public class RoleException : BaseIdentityException
    {
        public RoleException(string error)
            : base(error)
        {
        }

        public RoleException(string error, ErrorCodes errorCode)
            : base(error, errorCode)
        {
        }
    }
}