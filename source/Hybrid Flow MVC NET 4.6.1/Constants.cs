using System.Configuration;

namespace Hybrid_Flow
{
    public static class Constants
    {
        // ******************************************************************************************
        // This is currently the SIMS ID Partner environment, and will need to be updated for Live
        public static string BaseAddress = ConfigurationManager.AppSettings["sts-server"]; 
        // ******************************************************************************************

        public static readonly string AuthorizeEndpoint = BaseAddress + "/connect/authorize";
        public static readonly string LogoutEndpoint = BaseAddress + "/connect/endsession";
        public static readonly string TokenEndpoint = BaseAddress + "/connect/token";
        public static readonly string UserInfoEndpoint = BaseAddress + "/connect/userinfo";
        public static readonly string IdentityTokenValidationEndpoint = BaseAddress + "/connect/identitytokenvalidation";
        public static readonly string TokenRevocationEndpoint = BaseAddress + "/connect/revocation";
    }
}