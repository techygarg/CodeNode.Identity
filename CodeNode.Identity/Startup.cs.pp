using System.Threading.Tasks;
using System.Web.Cors;
using Microsoft.Owin;
using Microsoft.Owin.Cors;
using Owin;
using CodeNode.Identity.Models;
using CodeNode.Identity.Provider;
using CodeNode.Identity.Utilities;
using $rootnamespace$;


[assembly: OwinStartup(typeof(Startup))]

namespace $rootnamespace$
{
    public class Startup
    {
        /// <summary>
        ///     Configurations the specified application.
        /// </summary>
        /// <param name="app">The application.</param>
        public void Configuration(IAppBuilder app)
        {
			var option = new CorsOptions
             {
                 PolicyProvider = new CorsPolicyProvider
                 {
                     PolicyResolver = context =>
                     {
                        // provide appropriate origin 
                         var policy = new CorsPolicy();
                         policy.Origins.Add("*");
                         policy.AllowAnyMethod = true;
                         policy.AllowAnyHeader = true;
                         policy.SupportsCredentials = true;
                         return Task.FromResult(policy);
                     }
                 }
             };
            app.UseCors(option);
            ConfigureUmlOAuthSettings<ApplicationUser>(app);
        }

		private static void ConfigureOAuthSettings<TUser>(IAppBuilder app) where TUser : ApplicationUser, IUser<Guid>
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
        }
    }
}