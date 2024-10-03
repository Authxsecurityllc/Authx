using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthXSSOServiceProvider.Saml.Cryptography
{
    public class SamlX509Certificate : X509Certificate2
    {
        public RSA RSA { get; protected set; }
    
        public SamlX509Certificate(X509Certificate2 certificate, RSA rsa): base(certificate)
        {
            RSA = rsa;
        }
        public RSA GetRSAPrivateKey()
        {
            return RSA;
        }
    }
}
