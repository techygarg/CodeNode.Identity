using System;
using CodeNode.Identity.Database;
using CodeNode.Identity.Models;
using Microsoft.AspNet.Identity.EntityFramework;

namespace CodeNode.Identity.Store
{
    public class ApplicationRoleStore<TUser> : RoleStore<ApplicationRole, Guid, ApplicationUserRole>
        where TUser : ApplicationUser
    {
        public ApplicationRoleStore(DatabaseContext<TUser> context)
            : base(context)
        {
        }
    }
}