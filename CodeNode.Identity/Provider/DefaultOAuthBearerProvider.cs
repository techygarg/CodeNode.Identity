using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using CodeNode.Identity.Models;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security.OAuth;

namespace CodeNode.Identity.Provider
{
    internal class DefaultOAuthBearerProvider<TUser> : OAuthBearerAuthenticationProvider
        where TUser : ApplicationUser, IUser<Guid>
    {
        public override Task ValidateIdentity(OAuthValidateIdentityContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            // code to invalidate multiple login by comparing security stamp claim and its current value in DB

            //var path = HttpContext.Current.Server.MapPath(string.Format("~/{0}", "Log.txt"));
            //File.AppendAllText(path, Environment.NewLine);
            //File.AppendAllText(path, "Requested fro ValidateIdentity at : " + DateTime.Now);

            //var securityStampClaim = context.Ticket.Identity.Claims.FirstOrDefault(x => x.Type == Constants.DefaultSecurityStampClaimType);
            //var userIdClaim = context.Ticket.Identity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);

            //if (securityStampClaim == null || userIdClaim == null)
            //{
            //    context.Rejected();
            //}

            //using (var manager = new IdentityManager<TUser>())
            //{
            //    var user = manager.ApplicationUserManager.Users.FirstOrDefault(x => x.Id == new Guid(userIdClaim.Value));
            //    if (!string.Equals(user.SecurityStamp, securityStampClaim.Value, StringComparison.CurrentCultureIgnoreCase))
            //    {
            //        context.Rejected();
            //        //context.SetError("Multiple login is not allowed.");
            //        File.AppendAllText(path, "Request rejected ........");
            //        File.AppendAllText(path, Environment.NewLine);
            //    }
            //}


            if (context.Ticket.Identity.Claims.Any(c => c.Issuer != ClaimsIdentity.DefaultIssuer))
            {
                context.Rejected();
            }
            return Task.FromResult<object>(null);
        }
    }
}