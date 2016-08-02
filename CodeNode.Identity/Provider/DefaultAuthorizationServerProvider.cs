using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Security.Claims;
using System.Threading.Tasks;
using CodeNode.Identity.Models;
using CodeNode.Identity.Utilities;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using Constants = CodeNode.Identity.Utilities.IdentityConstants;

namespace CodeNode.Identity.Provider
{
    /// <summary>
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    public class DefaultAuthorizationServerProvider<TUser> : OAuthAuthorizationServerProvider
        where TUser : ApplicationUser, IUser<Guid>
    {
        public DefaultAuthorizationServerProvider()
        {
            OnValidateAuthorizeRequest = ValidateAuthorizeRequest;
        }

        #region Private Method

        /// <summary>
        ///     Creates the properties.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        /// <returns></returns>
        private static AuthenticationProperties CreateProperties(string userName)
        {
            IDictionary<string, string> data = new Dictionary<string, string>
            {
                {"userName", userName}
            };
            return new AuthenticationProperties(data);
        }

        #endregion

        #region Public Method

        /// <summary>
        ///     Called to validate that the origin of the request is a registered "client_id", and that the correct credentials for
        ///     that client are
        ///     present on the request. If the web application accepts Basic authentication credentials,
        ///     context.TryGetBasicCredentials(out clientId, out clientSecret) may be called to acquire those values if present in
        ///     the request header. If the web
        ///     application accepts "client_id" and "client_secret" as form encoded POST parameters,
        ///     context.TryGetFormCredentials(out clientId, out clientSecret) may be called to acquire those values if present in
        ///     the request body.
        ///     If context.Validated is not called the request will not proceed further.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>
        ///     Task to enable asynchronous execution
        /// </returns>
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
        }

        /// <summary>
        ///     Called when a request to the Token endpoint arrives with a "grant_type" of "password". This occurs when the user
        ///     has provided name and password
        ///     credentials directly into the client application's user interface, and the client application is using those to
        ///     acquire an "access_token" and
        ///     optional "refresh_token". If the web application supports the
        ///     resource owner credentials grant type it must validate the context.Username and context.Password as appropriate. To
        ///     issue an
        ///     access token the context.Validated must be called with a new ticket containing the claims about the resource owner
        ///     which should be associated
        ///     with the access token. The application should take appropriate measures to ensure that the endpoint isn’t abused by
        ///     malicious callers.
        ///     The default behavior is to reject this grant type.
        ///     See also http://tools.ietf.org/html/rfc6749#section-4.3.2
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>
        ///     Task to enable asynchronous execution
        /// </returns>
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var identityManager = new IdentityManager<TUser>();
            var result = identityManager.ValidateUserCredentials(context.UserName, context.Password);

            if (!result.IsSucceeded)
            {
                context.SetError("invalid_grant", result.Error);
                return;
            }

            if (AppSettingsValueProvider.EnableTwoFactorVerification)
            {
                var code = context.Request.Headers.Get(AppSettingsValueProvider.TwoFactorHeaderName);
                if (string.IsNullOrWhiteSpace(code))
                {
                    context.SetError("invalid_grant", "OTP is missing.");
                    return;
                }

                var tokenResult = identityManager.ValidateTwoFactorToken(result.User.Id, code,
                    IdentityConstants.EmailTwoFactorProviderName, true);
                switch (tokenResult)
                {
                    case SignInStatus.Failure:
                        context.SetError("invalid_grant", "Invalid OTP.");
                        return;
                    case SignInStatus.LockedOut:
                        context.SetError("invalid_grant", "Account is currently locked.");
                        return;
                }
            }

            // update last login time of user
            result.User.LastLoggedOn = DateTime.Now;
            identityManager.UpdateUser(result.User);
            //identityManager.UpdateSecurityStamp(result.User.Id);


            var oAuthIdentity = identityManager.ApplicationUserManager.CreateIdentity(result.User, "Bearer");
            // email as claim so that we can retrieve it from token without DB hit
            oAuthIdentity.AddClaim(new Claim(Constants.EmailClaimType, result.User.Email, ClaimValueTypes.String));
            var ticket = new AuthenticationTicket(oAuthIdentity, null);

            context.Validated(ticket);
            identityManager.Dispose();
        }

        /// <summary>
        ///     Called at the final stage of a successful Token endpoint request. An application may implement this call in order
        ///     to do any final
        ///     modification of the claims being used to issue access or refresh tokens. This call may also be used in order to add
        ///     additional
        ///     response parameters to the Token endpoint's json response body.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>
        ///     Task to enable asynchronous execution
        /// </returns>
        public override async Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            var identityManager = new IdentityManager<TUser>();
            var applicationUser = identityManager.ApplicationUserManager.FindByName(context.Identity.Name);

            await base.TokenEndpoint(context);

            if (applicationUser != null)
            {
                var user = new LoggedInUserInfo
                {
                    FirstName = applicationUser.FirstName,
                    LastName = applicationUser.LastName,
                    EmailId = applicationUser.Email,
                    Roles = identityManager.ApplicationUserManager.GetRoles(applicationUser.Id)
                };

                var memoryStream = new MemoryStream();
                var dataContractJsonSerializer = new DataContractJsonSerializer(typeof(LoggedInUserInfo));

                dataContractJsonSerializer.WriteObject(memoryStream, user);
                memoryStream.Position = 0;
                context.AdditionalResponseParameters.Add("user", new StreamReader(memoryStream).ReadToEnd());
            }
        }

        #endregion
    }
}