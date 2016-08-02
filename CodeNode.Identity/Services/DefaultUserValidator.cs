using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;

namespace CodeNode.Identity.Services
{
    internal class DefaultUserValidator<TUser> : UserValidator<TUser, Guid> where TUser : class, IUser<Guid>
    {
        private readonly Func<TUser, IEnumerable<string>> _validator;

        public DefaultUserValidator(UserManager<TUser, Guid> appUserManager,
            Func<TUser, IEnumerable<string>> customValidator)
            : base(appUserManager)
        {
            _validator = customValidator;
        }

        public override async Task<IdentityResult> ValidateAsync(TUser user)
        {
            if (_validator != null)
            {
                var errors = _validator(user);
                if (errors.Any())
                {
                    return new IdentityResult(errors);
                }
            }
            return await base.ValidateAsync(user);
        }
    }
}