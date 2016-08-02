using System;
using CodeNode.Identity.Models;
using Microsoft.AspNet.Identity.EntityFramework;

namespace CodeNode.Identity.Database
{
    public class DatabaseContext<TUser> :
        IdentityDbContext<TUser, ApplicationRole, Guid, ApplicationUserLogin, ApplicationUserRole, ApplicationUserClaim>
        where TUser : ApplicationUser
    {
        public DatabaseContext()
            : base("IdentityDBConnection")
        {
        }

        public DatabaseContext(string connectionStringName)
            : base(connectionStringName)
        {
        }
    }
}