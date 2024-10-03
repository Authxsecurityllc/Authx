using AuthXSSOServiceProvider.Saml.Schemas;
using System;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Threading;

namespace AuthXSSOServiceProvider.Saml.Mvc
{
    public static class SamlResponseExtensions
    {
        public static ClaimsPrincipal CreateSession(this SamlAuthnResponse SamlAuthnResponse, TimeSpan? lifetime = null, bool isReferenceMode = false, bool isPersistent = false, ClaimsAuthenticationManager claimsAuthenticationManager = null)
        {
            if (Thread.CurrentPrincipal.Identity.IsAuthenticated)
            {
                throw new InvalidOperationException("There already exist an Authenticated user.");
            }

            if (SamlAuthnResponse.Status != SamlStatusCodes.Success)
            {
                throw new InvalidOperationException($"The Saml Response Status is not Success, the Response Status is: {SamlAuthnResponse.Status}.");
            }

            var principal = new ClaimsPrincipal(SamlAuthnResponse.ClaimsIdentity);

            if (principal.Identity == null || !principal.Identity.IsAuthenticated)
            {
                throw new InvalidOperationException("No Claims Identity created from Saml Response.");
            }

            var transformedPrincipal = claimsAuthenticationManager != null ? claimsAuthenticationManager.Authenticate(null, principal) : principal;
            var sessionSecurityToken = lifetime.HasValue ?
                new SessionSecurityToken(transformedPrincipal, lifetime.Value) :
                new SessionSecurityToken(transformedPrincipal, null, SamlAuthnResponse.SamlSecurityToken.ValidFrom, SamlAuthnResponse.SamlSecurityToken.ValidTo);
            sessionSecurityToken.IsReferenceMode = isReferenceMode;
            sessionSecurityToken.IsPersistent = isPersistent;
            FederatedAuthentication.SessionAuthenticationModule.AuthenticateSessionSecurityToken(sessionSecurityToken, true);
            return transformedPrincipal;
        }

        public static bool DeleteSession(this SamlResponse SamlResponse)
        {
            if (SamlResponse.Status == SamlStatusCodes.Success)
            {
                FederatedAuthentication.SessionAuthenticationModule.DeleteSessionTokenCookie();
                FederatedAuthentication.SessionAuthenticationModule.SignOut();
                return true;
            }
            return false;
        }
    }
}
