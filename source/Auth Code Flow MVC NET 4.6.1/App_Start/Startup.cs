using System.Collections.Generic;
using System.IdentityModel.Tokens;
using Hybrid_Flow_with_PKCE;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;

[assembly: OwinStartup(typeof(Startup))]
namespace Hybrid_Flow_with_PKCE
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Cookies",
                AuthenticationMode = Microsoft.Owin.Security.AuthenticationMode.Active
            });
        }
    }
}