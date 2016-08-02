using Owin;
using UserManagement;
using UserManagement.Identity;
using Microsoft.Owin;
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
            UserManagement.UmlStartUp<ApplicationUser>.ConfigureUmlOAuthSettings(app);
        }
    }
}