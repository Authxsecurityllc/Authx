using AuthXSSOServiceProvider.Saml.Schemas;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;

namespace AuthXSSOServiceProvider.Saml.MvcCore
{
    public static class SamlRequestExtensions
    {
        public static async Task<SamlLogoutRequest> DeleteSession(this SamlLogoutRequest SamlLogoutRequest, HttpContext httpContext)
        {
            await httpContext.SignOutAsync(SamlConstants.AuthenticationScheme);
            return SamlLogoutRequest;
        }
    }
}
