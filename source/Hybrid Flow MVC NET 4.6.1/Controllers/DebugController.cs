using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Web.Mvc;
using Hybrid_Flow.Models;

namespace Hybrid_Flow.Controllers
{
    [Authorize]
    public class DebugController : Controller
    {
        public ActionResult Tokens()
        {

            var model = new DebugTokens();
            if (User is ClaimsPrincipal claimsPrincipal)
            {
                var idTokenHandler = new JwtSecurityTokenHandler();
                var idToken = claimsPrincipal.Claims.FirstOrDefault(c => c.Type == "id_token");
                if (idToken != null)
                {
                    var idJsonToken = idTokenHandler.ReadToken(idToken.Value) as JwtSecurityToken;
                    model.IdToken = idJsonToken;
                }

                var accessTokenHandler = new JwtSecurityTokenHandler();
                var accessToken = claimsPrincipal.Claims.FirstOrDefault(c => c.Type == "access_token");
                if (accessToken != null)
                {
                    var accessJsonToken = accessTokenHandler.ReadToken(accessToken.Value) as JwtSecurityToken;
                    model.AccessToken = accessJsonToken;
                }

            }
            return View(model);
        }
    }
}