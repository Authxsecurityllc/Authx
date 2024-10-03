using AuthXSSOServiceProvider.Saml;
using AuthXSSOServiceProvider.Saml.Schemas.Metadata;
using AuthXSSOServiceProvider.Saml.Util;
using System;
using System.Configuration;
using System.IdentityModel.Claims;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.Web;
using System.Web.Helpers;

namespace WebApplication
{
    public static class IdentityConfig
    {
        public static SamlConfiguration SamlConfiguration { get; private set; } = new SamlConfiguration();

        public static void RegisterIdentity()
        {
            AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.Email;

            SamlConfiguration.Issuer = ConfigurationManager.AppSettings["Saml:Issuer"];
            //SamlConfiguration.SingleSignOnDestination = new Uri(ConfigurationManager.AppSettings["Saml:SingleSignOnDestination"]);
            //SamlConfiguration.SingleLogoutDestination = new Uri(ConfigurationManager.AppSettings["Saml:SingleLogoutDestination"]);

            SamlConfiguration.SignatureAlgorithm = ConfigurationManager.AppSettings["Saml:SignatureAlgorithm"];
            SamlConfiguration.SignAuthnRequest = true;
            SamlConfiguration.SigningCertificate = CertificateUtil.Load(HttpContext.Current.Server.MapPath(ConfigurationManager.AppSettings["Saml:SigningCertificateFile"]), ConfigurationManager.AppSettings["Saml:SigningCertificatePassword"]);
            //SamlConfiguration.DecryptionCertificates.Add(SamlConfiguration.SigningCertificate);

            //SamlConfiguration.SignatureValidationCertificates.Add(CertificateUtil.Load(HttpContext.Current.Server.MapPath(ConfigurationManager.AppSettings["Saml:SignatureValidationCertificate"])));

            SamlConfiguration.CertificateValidationMode = (X509CertificateValidationMode)Enum.Parse(typeof(X509CertificateValidationMode), ConfigurationManager.AppSettings["Saml:CertificateValidationMode"]);
            SamlConfiguration.RevocationMode = (X509RevocationMode)Enum.Parse(typeof(X509RevocationMode), ConfigurationManager.AppSettings["Saml:RevocationMode"]);

            SamlConfiguration.AllowedAudienceUris.Add(SamlConfiguration.Issuer);

            var entityDescriptor = new EntityDescriptor();
            entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(ConfigurationManager.AppSettings["Saml:IdPMetadata"]));
            if (entityDescriptor.IdPSsoDescriptor != null)
            {
                SamlConfiguration.AllowedIssuer = entityDescriptor.EntityId;
                SamlConfiguration.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
                SamlConfiguration.SingleLogoutDestination = entityDescriptor.IdPSsoDescriptor.SingleLogoutServices.First().Location;
                foreach (var signingCertificate in entityDescriptor.IdPSsoDescriptor.SigningCertificates)
                {
                    if (signingCertificate.IsValidLocalTime())
                    {
                        SamlConfiguration.SignatureValidationCertificates.Add(signingCertificate);
                    }
                }
                if (SamlConfiguration.SignatureValidationCertificates.Count <= 0)
                {
                    throw new Exception("The IdP signing certificates has expired.");
                }
                if(entityDescriptor.IdPSsoDescriptor.WantAuthnRequestsSigned.HasValue)
                {
                    SamlConfiguration.SignAuthnRequest = true;//entityDescriptor.IdPSsoDescriptor.WantAuthnRequestsSigned.Value;
                }
            }
            else
            {
                throw new Exception("IdPSsoDescriptor not loaded from metadata.");
            }
        }
    }
}