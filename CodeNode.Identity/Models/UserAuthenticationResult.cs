namespace CodeNode.Identity.Models
{
    public class UserAuthenticationResult<TUser> where TUser : ApplicationUser
    {
        public bool IsSucceeded { get; set; }
        public TUser User { get; set; }
        public string Error { get; set; }
    }
}