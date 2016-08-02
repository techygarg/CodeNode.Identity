using System;
using CodeNode.Identity.Models;
using CodeNode.Identity.Provider;
using CodeNode.Identity.Utilities;
using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using Owin;

namespace CodeNode.Identity
{
    public static class IdentityStartUp<TUser> where TUser : ApplicationUser, IUser<Guid>
    {
        /// <summary>
        ///     Configurations the specified application.
        /// </summary>
        /// <param name="app">The application.</param>
        public static void ConfigureOAuthSettings(IAppBuilder app)
        {
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                SlidingExpiration = AppSettingsValueProvider.AuthCookieSlidingExpiration,
                ExpireTimeSpan = TimeSpan.FromHours(AppSettingsValueProvider.AuthCookieLifeInHr)
            });

            app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions
            {
                TokenEndpointPath = new PathString("/token"),
                Provider = new DefaultAuthorizationServerProvider<TUser>(),
                AccessTokenExpireTimeSpan = TimeSpan.FromHours(AppSettingsValueProvider.OAuthTokenLifeTimeInHr),
                AllowInsecureHttp = true
            });

            // we can add custom logic to validate token in  DefaultOAuthBearerProvider
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions
            {
                Provider = new DefaultOAuthBearerProvider<TUser>()
            });

            //app.UseOAuthBearerTokens(new OAuthAuthorizationServerOptions
            //{
            //    TokenEndpointPath = new PathString("/token"),
            //    Provider = new DefaultAuthorizationServerProvider<TUser>(),
            //    AccessTokenExpireTimeSpan = TimeSpan.FromHours(AppSettingsValueProvider.OAuthTokenLifeTimeInHr),
            //    AllowInsecureHttp = true
            //});

            //app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));
            //app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);
        }
    }
}