using AuthXSSOServiceProvider.Saml;
using AuthXSSOServiceProvider.Saml.Mvc;
using AuthXSSOServiceProvider.Saml.Schemas;
using AuthXSSOServiceProvider.Saml.Util;
using System.Web.Mvc;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;

namespace WebApplication.Controllers
{
    [AllowAnonymous]
    public class IdPInitiatedController : Controller
    {
        public ActionResult Initiate()
        {
            var serviceProviderRealm = "https://sampledomain.com/service-provider";
            var binding = new SamlPostBinding();
            binding.RelayState = $"RPID={Uri.EscapeDataString(serviceProviderRealm)}";

            var config = new SamlConfiguration();

            config.Issuer = "http://sampledomain.com/this-application";
            config.SingleSignOnDestination = new Uri("https://test-adfs.com/adfs/ls/");
            config.SigningCertificate = CertificateUtil.Load(HttpContext.Server.MapPath("~/App_Data/AuthX-0mc3hiam.pfx"), "");
            config.SignatureAlgorithm = SamlSecurityAlgorithms.RsaSha256Signature;

            var appliesToAddress = "https://test-adfs.com/adfs/services/trust";

            var response = new SamlAuthnResponse(config);
            response.Status = SamlStatusCodes.Success;    
   
            var claimsIdentity = new ClaimsIdentity(CreateClaims());
            response.NameId = new Saml2NameIdentifier(claimsIdentity.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).Single(), NameIdentifierFormats.Persistent);
            response.ClaimsIdentity = claimsIdentity;
            var token = response.CreateSecurityToken(appliesToAddress);

            return binding.Bind(response).ToActionResult();
        }

        private IEnumerable<Claim> CreateClaims()
        {
            yield return new Claim(ClaimTypes.NameIdentifier, "Test User");
            yield return new Claim(ClaimTypes.Email, "user@domain.com");
        }
    }
}
