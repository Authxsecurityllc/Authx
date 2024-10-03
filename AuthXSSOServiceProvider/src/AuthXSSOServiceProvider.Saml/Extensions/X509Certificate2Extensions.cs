using AuthXSSOServiceProvider.Saml.Cryptography;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthXSSOServiceProvider.Saml
{
    public static class X509Certificate2Extensions
    {
        public static RSA GetSamlRSAPrivateKey(this X509Certificate2 certificate)
        {
            if(certificate is SamlX509Certificate)
            {
                return (certificate as SamlX509Certificate).GetRSAPrivateKey();
            }
            else
            {
                return certificate.GetRSAPrivateKey();
            }
        }
        public static bool IsValidLocalTime(this X509Certificate2 certificate)
        {
            var nowLocal = DateTime.Now;
            if (certificate.NotBefore <= nowLocal && certificate.NotAfter >= nowLocal)
            {
                return true;
            }

            return false;
        }
    }
}
