using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols;

namespace Hybrid_Flow_with_PKCE.Controllers
{
    public class AccountController : Controller
    {
        private string _clientId;
        private string _clientSecret;
        private OpenIdConnectConfiguration _config;
        private string _discoAddress;
        private string _redirectUri;
        private string _stsServer;
        private string _tokenEndpoint;
        private string _userInfoEndpoint;
        private string _authorizeEndpoint;
        private string _scopes;

        public AccountController()
        {
            Initialise();
        }

        public async Task LoadConfig()
        {
            await LoadOpenIdConnectConfigurationAsync();
        }

        public ActionResult LogIn()
        {
            var nonce = CryptoRandom.CreateRandomKeyString(64);
            Session["nonce"] = nonce;
            var request = new AuthorizeRequest(_authorizeEndpoint);
            var url = request.CreateAuthorizeUrl(
                _clientId,
                "code",
                _scopes,
                $"{_redirectUri}",
                responseMode: "form_post");

            return Redirect(url);
        }

        public async Task<ActionResult> Callback(string code)
        {
            var tokenClient = new TokenClient(
                _tokenEndpoint,
                _clientId,
                _clientSecret);
            var response = tokenClient.RequestAuthorizationCodeAsync(
                code,
                _redirectUri).Result;
            Session["idtoken"] = response.IdentityToken;
            await ValidateResponseAndSignInAsync(response);
            return RedirectToAction("Index", "Home");
        }

        [Authorize]
        public ActionResult LogOut()
        {
            var idToken = Session["idtoken"].ToString();
            var endSessionUri =
                $"{_stsServer}/connect/endsession?id_token_hint={idToken}";
            var authenticationManager = HttpContext.GetOwinContext().Authentication;
            authenticationManager.SignOut();
            return Redirect(endSessionUri);
        }

        private void Initialise()
        {
            if (string.IsNullOrEmpty(ConfigurationManager.AppSettings["sts-server"]) ||
                string.IsNullOrEmpty(ConfigurationManager.AppSettings["client-id"]) ||
                string.IsNullOrEmpty(ConfigurationManager.AppSettings["redirect-uri"]) ||
                string.IsNullOrEmpty(ConfigurationManager.AppSettings["client-secret"]) ||
                string.IsNullOrEmpty(ConfigurationManager.AppSettings["client-scopes"]))
            {
                throw new Exception("All required configuration values have not been set");
            }

            Uri authority;
            if (Uri.TryCreate(ConfigurationManager.AppSettings["sts-server"], UriKind.Absolute, out authority))
            {
                _stsServer = authority.ToString();
            }
            else
            {
                throw new Exception("The configured STS uri must be a valid absolute uri");
            }

            Uri redirectUri;
            if (Uri.TryCreate(ConfigurationManager.AppSettings["redirect-uri"], UriKind.Absolute, out redirectUri))
            {
                _redirectUri = redirectUri.ToString();
            }
            else
            {
                throw new Exception("The configured redirect uri must be a valid absolute uri");
            }
            

            _discoAddress = $"{_stsServer}/.well-known/openid-configuration";
            _clientId = ConfigurationManager.AppSettings["client-id"];
            _clientSecret = ConfigurationManager.AppSettings["client-secret"];
            _tokenEndpoint = $"{_stsServer}/connect/token";
            _userInfoEndpoint = $"{_stsServer}/connect/userinfo";
            _authorizeEndpoint = $"{_stsServer}/connect/authorize";
            _scopes = ConfigurationManager.AppSettings["client-scopes"];
        }

        private async Task LoadOpenIdConnectConfigurationAsync()
        {
            var manager = new ConfigurationManager<OpenIdConnectConfiguration>(_discoAddress);
            _config = await manager.GetConfigurationAsync();
        }

        private async Task ValidateResponseAndSignInAsync(TokenResponse response)
        {
            if (!string.IsNullOrWhiteSpace(response.IdentityToken))
            {
                var tokenClaims = ValidateToken(response.IdentityToken);
                var claims = new List<Claim>();

                if (!string.IsNullOrWhiteSpace(response.AccessToken))
                {
                    claims.AddRange(await GetUserInfoClaimsAsync(response.AccessToken));

                    claims.Add(new Claim("access_token", response.AccessToken));
                    claims.Add(new Claim("expires_at",
                        (DateTime.UtcNow.ToEpochTime() + response.ExpiresIn).ToDateTimeFromEpoch().ToString(CultureInfo.CurrentCulture)));
                }

                if (!string.IsNullOrWhiteSpace(response.IdentityToken))
                {
                    claims.Add(new Claim("id_token", response.IdentityToken));
                }

                if (!string.IsNullOrWhiteSpace(response.RefreshToken))
                {
                    claims.Add(new Claim("refresh_token", response.RefreshToken));
                }

                var id = new ClaimsIdentity(claims, "Cookies");

                Request.GetOwinContext().Authentication.SignIn(id);
            }
        }

        private async Task<List<Claim>> ValidateToken(string token)
        {
            await LoadConfig();

            var tokens = new List<X509SecurityToken>(
                from key in _config.JsonWebKeySet.Keys
                select new X509SecurityToken(new X509Certificate2(Convert.FromBase64String(key.X5c.First()))));

            var parameters = new TokenValidationParameters
            {
                ValidIssuer = _stsServer,
                ValidateIssuerSigningKey = true,
                IssuerSigningTokens = tokens
            };

            SecurityToken jwt;
            var principal = new JwtSecurityTokenHandler().ValidateToken(token, parameters, out jwt);

            // validate nonce
            var nonceClaim = principal.FindFirst("nonce");

            if (!string.Equals(nonceClaim.Value, nonceClaim.ToString(), StringComparison.Ordinal))
            {
                throw new Exception("invalid nonce");
            }
            return principal.Claims.ToList();
        }

        private async Task<IEnumerable<Claim>> GetUserInfoClaimsAsync(string accessToken)
        {
            var userInfoClient = new UserInfoClient(new Uri(_userInfoEndpoint), accessToken);

            var userInfo = await userInfoClient.GetAsync();

            var claims = new List<Claim>();
            userInfo.Claims.ToList().ForEach(ui => claims.Add(new Claim(ui.Item1, ui.Item2)));

            return claims;
        }
    }
}