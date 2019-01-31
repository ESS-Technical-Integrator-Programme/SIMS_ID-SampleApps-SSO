using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using Hybrid_Flow;
using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

[assembly: OwinStartup(typeof(Startup))]
namespace Hybrid_Flow
{
    public class Startup
    {
        private readonly string _clientId = ConfigurationManager.AppSettings["client-id"];
        private readonly string _clientSecret = ConfigurationManager.AppSettings["client-secret"];
        private readonly string _cientRedirectUri = ConfigurationManager.AppSettings["redirect-uri"];
        private readonly string _clientPostLogoutRedirectUri = ConfigurationManager.AppSettings["redirect-uri"];
        private readonly string _clientScopes = ConfigurationManager.AppSettings["client-scopes"];

        public void Configuration(IAppBuilder app)
        {
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap = new Dictionary<string, string>();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Cookies",
                ExpireTimeSpan = TimeSpan.FromMinutes(60),
                SlidingExpiration = true
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = _clientId,
                Authority = Constants.BaseAddress,
                RedirectUri = _cientRedirectUri,
                PostLogoutRedirectUri = _clientPostLogoutRedirectUri,
                ResponseType = "code id_token",
                Scope = _clientScopes,

                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "role"
                },

                SignInAsAuthenticationType = "Cookies",

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthorizationCodeReceived = async n =>
                    {
                        // use the code to get the access and refresh token
                        var tokenClient = new TokenClient(
                            Constants.TokenEndpoint,
                            _clientId,
                            _clientSecret);

                        var tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(
                            n.Code, n.RedirectUri);

                        if (tokenResponse.IsError)
                        {
                            throw new Exception(tokenResponse.Error);
                        }

                        // use the access token to retrieve claims from userinfo

                        var userInfoClient = new UserInfoClient(Constants.UserInfoEndpoint);

                        var userInfoResponse = await userInfoClient.GetAsync(tokenResponse.AccessToken);

                        // create new identity
                        var id = new ClaimsIdentity(n.AuthenticationTicket.Identity.AuthenticationType);
                        id.AddClaims(userInfoResponse.Claims);

                        id.AddClaim(new Claim("access_token", tokenResponse.AccessToken));

                        id.AddClaim(new Claim("expires_at", DateTime.Now.AddSeconds(tokenResponse.ExpiresIn).ToLocalTime().ToString(CultureInfo.InvariantCulture)));
                        id.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));
                        id.AddClaim(new Claim("sid", n.AuthenticationTicket.Identity.FindFirst("sid").Value));

                        n.AuthenticationTicket = new AuthenticationTicket(
                            new ClaimsIdentity(id.Claims, n.AuthenticationTicket.Identity.AuthenticationType, "name", "role"),
                            n.AuthenticationTicket.Properties);
                    },

                    RedirectToIdentityProvider = n =>
                    {
                        // if signing out, add the id_token_hint
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                        {
                            var idTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token");

                            if (idTokenHint != null)
                            {
                                n.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                            }
                        }

                        return Task.FromResult(0);
                    }
                }
            });
        }
    }
}