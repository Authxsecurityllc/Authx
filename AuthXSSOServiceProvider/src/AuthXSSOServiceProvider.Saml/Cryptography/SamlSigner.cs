using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
#if !NETFULL
using AuthXSSOServiceProvider.Saml.Schemas;
#endif

namespace AuthXSSOServiceProvider.Saml.Cryptography
{
    public class SamlSigner
    {
        public X509Certificate2 Certificate { get; protected set; }

        public string SignatureAlgorithm { get; set; }

#if !NETFULL
        static SamlSigner()
        {
            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA1SignatureDescription), SamlSecurityAlgorithms.RsaSha1Signature);
            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), SamlSecurityAlgorithms.RsaSha256Signature);
            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA384SignatureDescription), SamlSecurityAlgorithms.RsaSha384Signature);
            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA512SignatureDescription), SamlSecurityAlgorithms.RsaSha512Signature);
            CryptoConfig.AddAlgorithm(typeof(RSAPSSSHA256SignatureDescription), SamlSecurityAlgorithms.RsaPssSha256Signature);
        }
#endif

        public SamlSigner(X509Certificate2 certificate, string signatureAlgorithm)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));
            if (signatureAlgorithm == null) throw new ArgumentNullException(nameof(signatureAlgorithm));

            Certificate = certificate;
            SignatureAlgorithm = signatureAlgorithm;
        }

        public (AsymmetricSignatureFormatter, HashAlgorithm) CreateFormatter()
        {
            (var signatureDescription, var hashAlgorithm) = GetSignatureDescription();
            var formatter = signatureDescription.CreateFormatter(Certificate.GetSamlRSAPrivateKey());
            return (formatter, hashAlgorithm);
        }

        public (AsymmetricSignatureDeformatter, HashAlgorithm) CreateDeformatter()
        {
            (var signatureDescription, var hashAlgorithm) = GetSignatureDescription();
            var deformatter = signatureDescription.CreateDeformatter(Certificate.GetRSAPublicKey());
            return (deformatter, hashAlgorithm);
        }

        private (SignatureDescription, HashAlgorithm) GetSignatureDescription()
        {
            var signatureDescription = (SignatureDescription)CryptoConfig.CreateFromName(SignatureAlgorithm);
            var hashAlgorithm = signatureDescription.CreateDigest();
            return (signatureDescription, hashAlgorithm);
        }
    }
}
