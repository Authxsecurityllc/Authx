using AuthXSSOServiceProvider.Saml.Schemas;
using System;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Threading;

namespace AuthXSSOServiceProvider.Saml.Mvc
{
    public static class SamlRequestExtensions
    {
        public static SamlLogoutRequest DeleteSession(this SamlLogoutRequest SamlLogoutRequest)
        {
            FederatedAuthentication.SessionAuthenticationModule.DeleteSessionTokenCookie();
            FederatedAuthentication.SessionAuthenticationModule.SignOut();
            return SamlLogoutRequest;
        }
    }
}
