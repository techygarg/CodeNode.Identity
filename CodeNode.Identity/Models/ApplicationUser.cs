using System;
using Microsoft.AspNet.Identity.EntityFramework;

namespace CodeNode.Identity.Models
{
    /// <summary>
    /// </summary>
    public class ApplicationUser : IdentityUser<Guid, ApplicationUserLogin, ApplicationUserRole, ApplicationUserClaim>
    {
        public ApplicationUser()
        {
            Id = Guid.NewGuid();
        }

        public ApplicationUser(string userName)
            : this()
        {
            UserName = userName;
        }

        public string FirstName { get; set; }

        public string LastName { get; set; }

        public string Address { get; set; }

        public bool IsFirstLogin { get; set; }

        public bool IsActive { get; set; }

        public Guid CreatedBy { get; set; }

        public DateTime CreatedOn { get; set; }

        public Guid? LastModifiedBy { get; set; }

        public DateTime? LastModifiedOn { get; set; }

        public DateTime? LastLoggedOn { get; set; }
    }
}