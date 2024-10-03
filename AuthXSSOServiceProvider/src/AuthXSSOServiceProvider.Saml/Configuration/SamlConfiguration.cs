using AuthXSSOServiceProvider.Saml.Schemas;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.IdentityModel.Selectors;
using System.Security.Cryptography.Xml;
using System.Linq;
#if NETFULL
using System.IdentityModel.Configuration;
#else
using Microsoft.IdentityModel.Tokens;
#endif

namespace AuthXSSOServiceProvider.Saml
{
    public class SamlConfiguration
    {
        public string Issuer { get; set; }

        public Uri SingleSignOnDestination { get; set; }

        public Uri SingleLogoutDestination { get; set; }

        public SamlIndexedEndpoint ArtifactResolutionService { get; set; }

        public bool ValidateArtifact { get; set; } = true;

        public string SignatureAlgorithm { get; set; } = SamlSecurityAlgorithms.RsaSha256Signature;
        public string XmlCanonicalizationMethod { get; set; } = SignedXml.XmlDsigExcC14NTransformUrl;        

        public X509Certificate2 SigningCertificate { get; set; }
        [Obsolete("DecryptionCertificate is now outdated for supporting multiple decryption certificates. Please use DecryptionCertificates instead.")]
        public X509Certificate2 DecryptionCertificate
        {
            get { return DecryptionCertificates?.FirstOrDefault(); }
            set { DecryptionCertificates = new List<X509Certificate2> { value }; }
        }
        public List<X509Certificate2> DecryptionCertificates { get; set; } = new List<X509Certificate2>();
        public X509Certificate2 EncryptionCertificate { get; set; }

        public string AllowedIssuer { get; set; }

        public List<X509Certificate2> SignatureValidationCertificates { get; set; } = new List<X509Certificate2>();
        public X509CertificateValidationMode CertificateValidationMode { get; set; } = X509CertificateValidationMode.ChainTrust;
        public X509RevocationMode RevocationMode { get; set; } = X509RevocationMode.Online;
        public X509CertificateValidator CustomCertificateValidator { get; set; }
#if NETFULL
        public SecurityTokenResolver CustomIssuerTokenResolver { get; set; }
        public IdentityModelCaches TokenReplayCache { get; set; }
        public TimeSpan? TokenReplayCacheExpirationPeriod { get; set; }
#else
        public ITokenReplayCache TokenReplayCache { get; set; }
#endif
        public bool SaveBootstrapContext { get; set; } = false;

        public bool DetectReplayedTokens { get; set; } = false;

        public bool AudienceRestricted { get; set; } = true;
        public List<string> AllowedAudienceUris { get; set; } = new List<string>();
        public bool SignAuthnRequest { get; set; } = false;
        public SamlAuthnResponseSignTypes AuthnResponseSignType { get; set; } = SamlAuthnResponseSignTypes.SignResponse;
    }
}
