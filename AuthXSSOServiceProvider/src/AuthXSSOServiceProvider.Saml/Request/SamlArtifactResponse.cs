using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml
{
    public class SamlArtifactResponse : SamlResponse
    {
        public override string ElementName => Schemas.SamlConstants.Message.ArtifactResponse;

        public X509IncludeOption CertificateIncludeOption { get; set; }

        public SamlRequest InnerRequest { get; set; }

        public SamlArtifactResponse(SamlConfiguration config, SamlRequest request) : base(config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            CertificateIncludeOption = X509IncludeOption.EndCertOnly;

            InnerRequest = request;
            InnerRequest.Destination = null;
        }

        public override XmlDocument ToXml()
        {
            var envelope = new XElement(Schemas.SamlConstants.ProtocolNamespaceX + ElementName);
            envelope.Add(base.GetXContent());
            XmlDocument = envelope.ToXmlDocument();

            var innerRequestXml = InnerRequest.ToXml();
            var status = XmlDocument.DocumentElement[Schemas.SamlConstants.Message.Status, Schemas.SamlConstants.ProtocolNamespace.OriginalString];
            XmlDocument.DocumentElement.InsertAfter(XmlDocument.ImportNode(innerRequestXml.DocumentElement, true), status);

            if (Config.SigningCertificate != null)
            {
                SignArtifactResponse();
            }
            return XmlDocument;
        }

        protected internal void SignArtifactResponse()
        {
            Cryptography.SignatureAlgorithm.ValidateAlgorithm(Config.SignatureAlgorithm);
            Cryptography.XmlCanonicalizationMethod.ValidateCanonicalizationMethod(Config.XmlCanonicalizationMethod);
            XmlDocument = XmlDocument.SignDocument(Config.SigningCertificate, Config.SignatureAlgorithm, Config.XmlCanonicalizationMethod, CertificateIncludeOption, Id.Value);
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != ElementName)
            {
                throw new SamlRequestException("Not a Saml Artifact Response.");
            }
        }

        protected internal override void Read(string xml, bool validate = false, bool detectReplayedTokens = true)
        {
            base.Read(xml, validate, detectReplayedTokens);

            if (Status == Schemas.SamlStatusCodes.Success)
            {
                InnerRequest.Read(GetInnerArtifactElementXml().OuterXml, false, false);
            }
        }

        XmlElement assertionElementCache = null;
        protected override XmlElement GetAssertionElement()
        {
            if (assertionElementCache == null)
            {
                if (Status == Schemas.SamlStatusCodes.Success && InnerRequest is SamlAuthnResponse)
                {
#if NETFULL || NETSTANDARD || NETCORE || NET50 || NET60
                    assertionElementCache = GetAssertionElementReference().ToXmlDocument().DocumentElement;
#else
                    assertionElementCache = GetAssertionElementReference();
#endif
                }
            }
            return assertionElementCache;
        }

        private XmlElement GetAssertionElementReference()
        {
            var assertionElements = GetInnerArtifactElementXml().SelectNodes($"//*[local-name()='{Schemas.SamlConstants.Message.Assertion}']/ancestor-or-self::*[local-name()='{Schemas.SamlConstants.Message.Assertion}'][last()]");
            if (assertionElements.Count != 1)
            {
                throw new SamlRequestException("Assertion element is more than one in the inner Artifact element.");
            }
            return assertionElements[0] as XmlElement;
        }

        XmlNode innerArtifactElementCache = null;
        private XmlNode GetInnerArtifactElementXml()
        {
            if (innerArtifactElementCache == null)
            {
                var innerElements = XmlDocument.DocumentElement.SelectNodes(string.Format("//*[local-name()='{0}']", InnerRequest.ElementName));
                if (innerElements?.Count != 1)
                {
                    throw new SamlRequestException("There is not exactly one inner artifact element.");
                }
                innerArtifactElementCache = innerElements[0];
            }

            return innerArtifactElementCache;
        }
    }
}
