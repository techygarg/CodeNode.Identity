using System;
using Microsoft.AspNet.Identity.EntityFramework;

namespace CodeNode.Identity.Models
{
    public class ApplicationRole : IdentityRole<Guid, ApplicationUserRole>
    {
        public ApplicationRole()
        {
            Id = Guid.NewGuid();
        }

        public ApplicationRole(string name)
            : this()
        {
            Name = name;
        }
    }
}