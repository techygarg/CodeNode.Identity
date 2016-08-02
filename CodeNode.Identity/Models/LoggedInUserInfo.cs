using System.Collections.Generic;

namespace CodeNode.Identity.Models
{
    public class LoggedInUserInfo
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string EmailId { get; set; }
        public IEnumerable<string> Roles { get; set; }
    }
}