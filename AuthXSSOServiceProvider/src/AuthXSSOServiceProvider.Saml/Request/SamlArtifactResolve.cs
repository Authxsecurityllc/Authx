using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;
using AuthXSSOServiceProvider.Saml.Schemas;
using System;
using System.Security.Cryptography.X509Certificates;
using AuthXSSOServiceProvider.Saml.Configuration;
using System.Linq;
using AuthXSSOServiceProvider.Saml.Util;

namespace AuthXSSOServiceProvider.Saml
{
    public class SamlArtifactResolve : SamlRequest
    {
        public override string ElementName => SamlConstants.Message.ArtifactResolve;
        public X509IncludeOption CertificateIncludeOption { get; set; }
        public string Artifact { get; set; }

        public SamlArtifactResolve(SamlConfiguration config) : base(config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            CertificateIncludeOption = X509IncludeOption.EndCertOnly;

            Destination = config.SingleSignOnDestination;  
        }
        protected internal virtual void CreateArtifact()
        {
            var artifactBytes = new byte[44];
            artifactBytes[1] = 4;
            artifactBytes[2] = (byte)(Config.ArtifactResolutionService.Index >> 8);
            artifactBytes[3] = (byte)Config.ArtifactResolutionService.Index;

            if (string.IsNullOrEmpty(Issuer)) throw new ArgumentNullException("Issuer property");
            Array.Copy(Issuer.ComputeSha1Hash(), 0, artifactBytes, 4, 20);

            Array.Copy(RandomGenerator.GenerateArtifactMessageHandle(), 0, artifactBytes, 24, 20);

            Artifact = Convert.ToBase64String(artifactBytes);
        }
        protected internal virtual void ValidateArtifact()
        {
            if (Config.ValidateArtifact)
            {
                var artifactBytes = Convert.FromBase64String(Artifact);

                if (artifactBytes[1] != 4)
                {
                    throw new SamlRequestException("Invalid Artifact type, not type. Artifact validation can be disabled in config.");
                }

                if (string.IsNullOrEmpty(Config.AllowedIssuer))
                {
                    throw new SamlConfigurationException("Unable to validate Artifact SourceId/Issuer. AllowedIssuer not configured.");
                }
                var sourceIdBytes = new byte[20];
                Array.Copy(artifactBytes, 4, sourceIdBytes, 0, 20);
                if (!sourceIdBytes.SequenceEqual(Config.AllowedIssuer.ComputeSha1Hash()))
                {
                    throw new SamlRequestException($"Invalid SourceId/Issuer. Actually '{Issuer}', allowed '{Config.AllowedIssuer}'");
                }

                var arsIndex = (artifactBytes[2] << 8) | artifactBytes[3];
                if (arsIndex != Config.ArtifactResolutionService.Index)
                {
                    throw new SamlRequestException($"Invalid ArtifactResolutionService Index. Actually '{arsIndex}', expected '{Config.ArtifactResolutionService.Index}'");
                }
            }
        }

        public override XmlDocument ToXml()
        {
            var envelope = new XElement(SamlConstants.ProtocolNamespaceX + ElementName);
            envelope.Add(base.GetXContent());
            envelope.Add(GetXContent());

            XmlDocument = envelope.ToXmlDocument();
            if (Config.SigningCertificate != null)
            {
                SignArtifactResolve();
            }
            return XmlDocument;
        }

        protected internal void SignArtifactResolve()
        {
            Cryptography.SignatureAlgorithm.ValidateAlgorithm(Config.SignatureAlgorithm);
            Cryptography.XmlCanonicalizationMethod.ValidateCanonicalizationMethod(Config.XmlCanonicalizationMethod);
            XmlDocument = XmlDocument.SignDocument(Config.SigningCertificate, Config.SignatureAlgorithm, Config.XmlCanonicalizationMethod, CertificateIncludeOption, Id.Value);
        }

        protected override IEnumerable<XObject> GetXContent()
        {
            yield return new XElement(SamlConstants.ProtocolNamespaceX + SamlConstants.Message.Artifact, Artifact);
        }

        protected internal override void Read(string xml, bool validate = false, bool detectReplayedTokens = true)
        {
            base.Read(xml, validate, detectReplayedTokens);

            Artifact = XmlDocument.DocumentElement[SamlConstants.Message.Artifact, SamlConstants.ProtocolNamespace.OriginalString].GetValueOrNull<string>();
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != ElementName)
            {
                throw new SamlRequestException("Not a Saml Artifact Resolve Request.");
            }
        }
    }
}
