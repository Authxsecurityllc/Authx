using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace WebApplication.Identity
{
    public class DefaultClaimsAuthenticationManager : ClaimsAuthenticationManager
    {
        public override ClaimsPrincipal Authenticate(string resourceName, ClaimsPrincipal incomingPrincipal)
        {
            if (!incomingPrincipal.Identity.IsAuthenticated)
            {
                return incomingPrincipal;
            }

            return CreateClaimsPrincipal(incomingPrincipal);
        }

        private ClaimsPrincipal CreateClaimsPrincipal(ClaimsPrincipal incomingPrincipal)
        {
            var claims = new List<Claim>();
            claims.AddRange(incomingPrincipal.Claims);

            //custom claims
            //claims.AddRange(GetSamlLogoutClaims(incomingPrincipal));
            //claims.Add(new Claim(ClaimTypes.NameIdentifier, GetClaimValue(incomingPrincipal, ClaimTypes.NameIdentifier)));

            return new ClaimsPrincipal(new ClaimsIdentity(claims, incomingPrincipal.Identity.AuthenticationType, ClaimTypes.NameIdentifier, ClaimTypes.Role)
            {
                BootstrapContext = ((ClaimsIdentity)incomingPrincipal.Identity).BootstrapContext
            });
        }

        private IEnumerable<Claim> GetSamlLogoutClaims(ClaimsPrincipal principal)
        {
            yield return GetClaim(principal, ClaimTypes.NameIdentifier);
            yield return GetClaim(principal, ClaimTypes.Email);
        }

        private Claim GetClaim(ClaimsPrincipal principal, string claimType)
        {
            return ((ClaimsIdentity)principal.Identity).Claims.Where(c => c.Type == claimType).FirstOrDefault();
        }

        private string GetClaimValue(ClaimsPrincipal principal, string claimType)
        {
            var claim = GetClaim(principal, claimType);
            return claim != null ? claim.Value : null;
        }
    }
}