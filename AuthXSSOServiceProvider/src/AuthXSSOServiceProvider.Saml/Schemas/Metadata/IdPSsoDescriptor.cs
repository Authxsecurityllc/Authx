using System;
using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Metadata
{
    public class IdPSsoDescriptor : SsoDescriptorType
    {
        const string elementName = SamlMetadataConstants.Message.IdPSsoDescriptor;
        public bool? WantAuthnRequestsSigned { get; set; }
        public IEnumerable<SingleSignOnService> SingleSignOnServices { get; set; }

        public IEnumerable<SamlAttribute> Attributes { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlMetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(SamlMetadataConstants.Message.ProtocolSupportEnumeration, protocolSupportEnumeration);

            if (WantAuthnRequestsSigned.HasValue)
            {
                yield return new XAttribute(SamlMetadataConstants.Message.WantAuthnRequestsSigned, WantAuthnRequestsSigned.Value);
            }

            if (Extensions != null)
            {
                yield return Extensions.ToXElement();
            }

            if (EncryptionCertificates != null)
            {
                foreach (var encryptionCertificate in EncryptionCertificates)
                {
                    yield return KeyDescriptor(encryptionCertificate, SamlMetadataConstants.KeyTypes.Encryption, EncryptionMethods);
                }
            }

            if (SigningCertificates != null)
            {
                foreach (var signingCertificate in SigningCertificates)
                {
                    yield return KeyDescriptor(signingCertificate, SamlMetadataConstants.KeyTypes.Signing);
                }
            }

            if (SingleLogoutServices != null)
            {
                foreach (var singleLogoutService in SingleLogoutServices)
                {
                    yield return singleLogoutService.ToXElement();
                }
            }

            if (ArtifactResolutionServices != null)
            {
                foreach (var artifactResolutionService in ArtifactResolutionServices)
                {
                    yield return artifactResolutionService.ToXElement();
                }
            }

            if (NameIDFormats != null)
            {
                foreach (var nameIDFormat in NameIDFormats)
                {
                    yield return new XElement(SamlMetadataConstants.MetadataNamespaceX + SamlMetadataConstants.Message.NameIDFormat, nameIDFormat.OriginalString);
                }
            }

            if (SingleSignOnServices != null)
            {
                foreach (var singleSignOnService in SingleSignOnServices)
                {
                    yield return singleSignOnService.ToXElement();
                }
            }

            if (Attributes != null)
            {
                foreach (var attribute in Attributes)
                {
                    yield return attribute.ToXElement();
                }
            }
        }

        protected internal IdPSsoDescriptor Read(XmlElement xmlElement)
        {
            WantAuthnRequestsSigned = xmlElement.Attributes[SamlMetadataConstants.Message.WantAuthnRequestsSigned]?.Value.Equals(true.ToString(), StringComparison.InvariantCultureIgnoreCase);

            ReadKeyDescriptors(xmlElement);

            var singleSignOnServiceElements = xmlElement.SelectNodes($"*[local-name()='{SamlMetadataConstants.Message.SingleSignOnService}']");
            if (singleSignOnServiceElements != null)
            {
                SingleSignOnServices = ReadServices<SingleSignOnService>(singleSignOnServiceElements);
            }

            ReadArtifactResolutionService(xmlElement);

            ReadSingleLogoutService(xmlElement);

            ReadNameIDFormat(xmlElement);

            return this;
        }      
    }
}
