using System.IdentityModel.Tokens;

namespace Hybrid_Flow_with_PKCE.Models
{
    public class DebugTokens
    {
        public JwtSecurityToken IdToken { get; set; }
        public JwtSecurityToken AccessToken { get; set; }
    }
}