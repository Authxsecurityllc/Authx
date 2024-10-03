using AuthXSSOServiceProvider.Saml.Schemas;
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AuthXSSOServiceProvider.Saml.MvcCore
{
    public static class SamlResponseExtensions
    {
        public static async Task<ClaimsPrincipal> CreateSession(this SamlAuthnResponse SamlAuthnResponse, HttpContext httpContext, TimeSpan? lifetime = null, bool isPersistent = false, Func<ClaimsPrincipal, ClaimsPrincipal> claimsTransform = null)
        {
            if (httpContext.User.Identity.IsAuthenticated)
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

            if (claimsTransform != null)
            {
                principal = claimsTransform(principal);
            }

            await httpContext.SignInAsync(SamlConstants.AuthenticationScheme, principal,
                new AuthenticationProperties
                {
                    AllowRefresh = true,
                    IsPersistent = isPersistent,
                    IssuedUtc = SamlAuthnResponse.SecurityTokenValidFrom,
                    ExpiresUtc = lifetime.HasValue ? DateTimeOffset.UtcNow.Add(lifetime.Value) : SamlAuthnResponse.SecurityTokenValidTo,
                });

            return principal;
        }
    }
}
