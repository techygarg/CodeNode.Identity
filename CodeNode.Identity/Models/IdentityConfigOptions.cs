using System;
using System.Collections.Generic;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

namespace CodeNode.Identity.Models
{
    public class IdentityConfigOptions<TUser> where TUser : ApplicationUser, IUser<Guid>
    {
        public Func<TUser, IEnumerable<string>> UserValidatorExtender;
        public IIdentityValidator<string> PasswordValidator { get; set; }
        public IIdentityMessageService EmailService { get; set; }
        public DataProtectorTokenProvider<TUser, Guid> UserTokenProvider { get; set; }
    }
}