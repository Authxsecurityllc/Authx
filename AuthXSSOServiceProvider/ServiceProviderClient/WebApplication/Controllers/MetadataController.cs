using AuthXSSOServiceProvider.Saml;
using AuthXSSOServiceProvider.Saml.Mvc;
using AuthXSSOServiceProvider.Saml.Schemas;
using AuthXSSOServiceProvider.Saml.Schemas.Metadata;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Web.Mvc;

namespace WebApplication.Controllers
{
    [AllowAnonymous]
    public class MetadataController : Controller
    {
        private readonly SamlConfiguration config;

        public MetadataController()
        {
            config = IdentityConfig.SamlConfiguration;
        }

        public ActionResult Index()
        {
            var defaultSite = new Uri($"{Request.Url.Scheme}://{Request.Url.Authority}");

            var entityDescriptor = new EntityDescriptor(config);
            entityDescriptor.ValidUntil = 365;
            entityDescriptor.SPSsoDescriptor = new SPSsoDescriptor
            {
                WantAssertionsSigned = true,
                AuthnRequestsSigned = true,
                SigningCertificates = new X509Certificate2[]
                {
                    config.SigningCertificate
                },
                //EncryptionCertificates = config.DecryptionCertificates,
                SingleLogoutServices = new SingleLogoutService[]
                {
                    new SingleLogoutService { Binding = ProtocolBindings.HttpPost, Location = new Uri(defaultSite, "Auth/SingleLogout") }
                },
                NameIDFormats = new Uri[] { NameIdentifierFormats.Email },
                AssertionConsumerServices = new AssertionConsumerService[]
                {
                    new AssertionConsumerService {  Binding = ProtocolBindings.HttpPost, Location = new Uri(defaultSite, "Auth/AssertionConsumerService") }
                },
            };
            return new SamlMetadata(entityDescriptor).CreateMetadata().ToActionResult();
        }
    }
}