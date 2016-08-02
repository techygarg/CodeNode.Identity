using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using CodeNode.Identity.Models;
using Microsoft.AspNet.Identity;

namespace CodeNode.Identity.Utilities
{
    /// <summary>
    ///     Helper to get user claims from current identity
    /// </summary>
    public class IdentityClaimsHelper
    {
        private static readonly ClaimsIdentityFactory<ApplicationUser, Guid> ClaimFactory =
            new ClaimsIdentityFactory<ApplicationUser, Guid>();

        /// <summary>
        ///     Gets the current user identifier.
        /// </summary>
        /// <returns></returns>
        /// s
        public static Guid GetCurrentUserId()
        {
            var claimIdentity = new ClaimsIdentity(Thread.CurrentPrincipal.Identity);
            var userIdClaim = claimIdentity.Claims.FirstOrDefault(x => x.Type == ClaimFactory.UserIdClaimType);

            return userIdClaim != null ? new Guid(userIdClaim.Value) : Guid.Empty;
        }

        /// <summary>
        ///     Gets the name of the current user.
        /// </summary>
        /// <returns></returns>
        public static string GetCurrentUserName()
        {
            var userName = string.Empty;
            var claimIdentity = new ClaimsIdentity(Thread.CurrentPrincipal.Identity);
            var userNameClaim = claimIdentity.Claims.FirstOrDefault(x => x.Type == ClaimFactory.UserNameClaimType);

            if (userNameClaim != null)
            {
                userName = userNameClaim.Value;
            }
            return userName;
        }

        /// <summary>
        ///     Gets the current user email.
        /// </summary>
        /// <returns></returns>
        public static string GetCurrentUserEmail()
        {
            var userEmail = string.Empty;
            var claimIdentity = new ClaimsIdentity(Thread.CurrentPrincipal.Identity);
            var userEmailClaim = claimIdentity.Claims.FirstOrDefault(x => x.Type == IdentityConstants.EmailClaimType);

            if (userEmailClaim != null)
            {
                userEmail = userEmailClaim.Value;
            }
            return userEmail;
        }

        /// <summary>
        ///     Gets the current user roles.
        /// </summary>
        /// <returns></returns>
        public static List<string> GetCurrentUserRoles()
        {
            var claimIdentity = new ClaimsIdentity(Thread.CurrentPrincipal.Identity);
            var userRoleClaims = claimIdentity.Claims.Where(x => x.Type == ClaimFactory.RoleClaimType);
            return userRoleClaims.Select(roleClaim => roleClaim.Value).ToList();
        }
    }
}