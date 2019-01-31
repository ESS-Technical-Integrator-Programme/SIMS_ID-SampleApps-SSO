using System.IdentityModel.Tokens.Jwt;

namespace Hybrid_Flow.Models
{
    public class DebugTokens
    {
        public JwtSecurityToken IdToken { get; set; }
        public JwtSecurityToken AccessToken { get; set; }
    }
}