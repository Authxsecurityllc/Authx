using AuthXSSOServiceProvider.Saml.Configuration;
using AuthXSSOServiceProvider.Saml.Cryptography;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
using System.Security.Cryptography.Xml;
#if NETFULL
using System.IdentityModel.Tokens;
#else
using Microsoft.IdentityModel.Tokens.Saml2;
#endif

namespace AuthXSSOServiceProvider.Saml
{
    public abstract class SamlRequest
    {
        public abstract string ElementName { get; }

        public SamlConfiguration Config { get; protected set; }

        public XmlDocument XmlDocument { get; protected set; }
        public Saml2Id Id { get; set; }
        public string IdAsString
        {
            get { return Id.Value; }
            set { Id = new Saml2Id(value); }
        }
        public string Version { get; set; }
        public DateTimeOffset IssueInstant { get; set; }
        public Uri Destination { get; set; }
        public string Consent { get; set; }
        public string Issuer { get; set; }
        public Schemas.Extensions Extensions { get; set; }
        public Saml2NameIdentifier NameId { get; set; }
        public string SessionIndex { get; set; }

        public IEnumerable<X509Certificate2> SignatureValidationCertificates { get; set; }

        public string SignatureAlgorithm { get; set; }

        public string XmlCanonicalizationMethod { get; set; }

        internal SamlIdentityConfiguration IdentityConfiguration { get; private set; }

        protected SamlRequest(SamlConfiguration config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            Config = config;
            Issuer = config.Issuer;
            Issuer = config.Issuer;
            IdentityConfiguration = SamlIdentityConfiguration.GetIdentityConfiguration(config);

            Id = new Saml2Id();
            Version = Schemas.SamlConstants.VersionNumber;
            IssueInstant = DateTimeOffset.UtcNow;
        }

        protected virtual IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Schemas.SamlConstants.ProtocolNamespaceNameX, Schemas.SamlConstants.ProtocolNamespace.OriginalString);
            yield return new XAttribute(Schemas.SamlConstants.AssertionNamespaceNameX, Schemas.SamlConstants.AssertionNamespace.OriginalString);
            yield return new XAttribute(Schemas.SamlConstants.Message.Id, IdAsString);
            yield return new XAttribute(Schemas.SamlConstants.Message.Version, Version);
            yield return new XAttribute(Schemas.SamlConstants.Message.IssueInstant, IssueInstant.UtcDateTime.ToString(Schemas.SamlConstants.DateTimeFormat, CultureInfo.InvariantCulture));

            if (!string.IsNullOrWhiteSpace(Consent))
            {
                yield return new XAttribute(Schemas.SamlConstants.Message.Consent, Consent);
            }

            if (Destination != null)
            {
                yield return new XAttribute(Schemas.SamlConstants.Message.Destination, Destination);
            }

            if (Issuer != null)
            {
                yield return new XElement(Schemas.SamlConstants.AssertionNamespaceX + Schemas.SamlConstants.Message.Issuer, Issuer);
            }

            if (Extensions != null)
            {
                yield return Extensions.ToXElement();
            }
        }

        public abstract XmlDocument ToXml();

        protected internal virtual void Read(string xml, bool validate, bool detectReplayedTokens)
        {
            XmlDocument = xml.ToXmlDocument();

            ValidateProtocol();

            ValidateElementName();

            Id = XmlDocument.DocumentElement.Attributes[Schemas.SamlConstants.Message.Id].GetValueOrNull<Saml2Id>();

            Version = XmlDocument.DocumentElement.Attributes[Schemas.SamlConstants.Message.Version].GetValueOrNull<string>();
            if (Version != Schemas.SamlConstants.VersionNumber)
            {
                throw new SamlRequestException("Invalid Saml version.");
            }

            IssueInstant = XmlDocument.DocumentElement.Attributes[Schemas.SamlConstants.Message.IssueInstant].GetValueOrNull<DateTimeOffset>();

            Issuer = XmlDocument.DocumentElement[Schemas.SamlConstants.Message.Issuer, Schemas.SamlConstants.AssertionNamespace.OriginalString].GetValueOrNull<string>();
            if (!string.IsNullOrEmpty(Config.AllowedIssuer) && !Config.AllowedIssuer.Equals(Issuer, StringComparison.Ordinal))
            {
                throw new SamlRequestException($"Invalid Issuer. Actually '{Issuer}', allowed '{Config.AllowedIssuer}'");
            }

            Destination = XmlDocument.DocumentElement.Attributes[Schemas.SamlConstants.Message.Destination].GetValueOrNull<Uri>();

            var extensionsElement = XmlDocument.DocumentElement[Schemas.SamlConstants.Message.Extensions, Schemas.SamlConstants.ProtocolNamespace.OriginalString];
            if (extensionsElement != null)
            {
                Extensions = new Schemas.Extensions { Element = extensionsElement.ToXmlDocument().ToXElement() };
            }

            var documentValidationResult = MustValidateXmlSignature(validate) ? ValidateXmlSignature(XmlDocument.DocumentElement) : SignatureValidation.NotPresent;

            DecryptMessage();

            if (MustValidateXmlSignature(validate))
            {
                ValidateXmlSignature(documentValidationResult);
            }
        }

        protected virtual void ValidateProtocol()
        {
            if (XmlDocument.DocumentElement.NamespaceURI != Schemas.SamlConstants.ProtocolNamespace.OriginalString)
            {
                throw new SamlRequestException("Invalid Saml Protocol.");
            }
        }

        protected abstract void ValidateElementName();

        protected virtual void DecryptMessage()
        { }

        protected virtual XmlElement GetAssertionElement()
        {
            return null;
        }

        private bool MustValidateXmlSignature(bool validate)
        {
            return (!(this is SamlAuthnRequest) || Config.SignAuthnRequest) && validate;
        }

        private void ValidateXmlSignature(SignatureValidation documentValidationResult)
        {
            var assertionElement = GetAssertionElement();
            if(assertionElement == null)
            {
                if (documentValidationResult != SignatureValidation.Valid)
                    throw new InvalidSignatureException("Signature is invalid.");
            }
            else
            {
                var assertionValidationResult = ValidateXmlSignature(assertionElement);
                if (documentValidationResult == SignatureValidation.Invalid || assertionValidationResult == SignatureValidation.Invalid || 
                    !(documentValidationResult == SignatureValidation.Valid || assertionValidationResult == SignatureValidation.Valid))
                    throw new InvalidSignatureException("Signature is invalid.");
            }
        }

        protected SignatureValidation ValidateXmlSignature(XmlElement xmlElement)
        {
            var xmlSignatures = xmlElement.SelectNodes($"*[local-name()='{Schemas.SamlConstants.Message.Signature}' and namespace-uri()='{SignedXml.XmlDsigNamespaceUrl}']");
            if (xmlSignatures.Count == 0)
            {
                return SignatureValidation.NotPresent;
            }
            if (xmlSignatures.Count > 1)
            {
                throw new InvalidSignatureException("There is more than one Signature element.");
            }

            foreach (var signatureValidationCertificate in SignatureValidationCertificates)
            {
                var signedXml = new SamlSignedXml(xmlElement, signatureValidationCertificate, SignatureAlgorithm, XmlCanonicalizationMethod);
                signedXml.LoadXml(xmlSignatures[0] as XmlElement);
                if (signedXml.CheckSignature())
                {
                    IdentityConfiguration.CertificateValidator.Validate(signatureValidationCertificate);

                    return SignatureValidation.Valid;
                }
            }
            return SignatureValidation.Invalid;
        }

        protected enum SignatureValidation
        {
            Valid,
            Invalid,
            NotPresent
        }
    }
}
