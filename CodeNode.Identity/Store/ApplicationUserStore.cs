using System;
using CodeNode.Identity.Database;
using CodeNode.Identity.Models;
using Microsoft.AspNet.Identity.EntityFramework;

namespace CodeNode.Identity.Store
{
    public class ApplicationUserStore<TUser> :
        UserStore<TUser, ApplicationRole, Guid, ApplicationUserLogin, ApplicationUserRole, ApplicationUserClaim>
        where TUser : ApplicationUser
    {
        public ApplicationUserStore(DatabaseContext<TUser> context)
            : base(context)
        {
        }
    }
}