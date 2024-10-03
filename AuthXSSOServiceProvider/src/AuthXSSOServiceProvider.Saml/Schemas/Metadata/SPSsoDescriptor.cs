using System;
using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Metadata
{
    public class SPSsoDescriptor : SsoDescriptorType
    {
        const string elementName = SamlMetadataConstants.Message.SPSsoDescriptor;

        public bool? AuthnRequestsSigned { get; set; }
        public bool? WantAssertionsSigned { get; set; }

        public IEnumerable<AssertionConsumerService> AssertionConsumerServices { get; set; }
        public IEnumerable<AttributeConsumingService> AttributeConsumingServices { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlMetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(SamlMetadataConstants.Message.ProtocolSupportEnumeration, protocolSupportEnumeration);

            if(AuthnRequestsSigned.HasValue)
            {
                yield return new XAttribute(SamlMetadataConstants.Message.AuthnRequestsSigned, AuthnRequestsSigned.Value);
            }

            if (WantAssertionsSigned.HasValue)
            {
                yield return new XAttribute(SamlMetadataConstants.Message.WantAssertionsSigned, WantAssertionsSigned.Value);
            }

            if (Extensions != null)
            {
                yield return Extensions.ToXElement();
            }
            
            if (EncryptionCertificates != null)
            {
                foreach(var encryptionCertificate in EncryptionCertificates)
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

            if (AssertionConsumerServices == null)
            {
                throw new ArgumentNullException("AssertionConsumerService property");
            }
            var index = 0;
            foreach (var assertionConsumerService in AssertionConsumerServices)
            {
                yield return assertionConsumerService.ToXElement(index++);
            }
        }


        protected internal SPSsoDescriptor Read(XmlElement xmlElement)
        {
            AuthnRequestsSigned = xmlElement.Attributes[SamlMetadataConstants.Message.AuthnRequestsSigned]?.Value.Equals(true.ToString(), StringComparison.InvariantCultureIgnoreCase);

            WantAssertionsSigned = xmlElement.Attributes[SamlMetadataConstants.Message.WantAssertionsSigned]?.Value.Equals(true.ToString(), StringComparison.InvariantCultureIgnoreCase);

            ReadKeyDescriptors(xmlElement);

            var assertionConsumerServicesElements = xmlElement.SelectNodes($"*[local-name()='{SamlMetadataConstants.Message.AssertionConsumerService}']");
            if (assertionConsumerServicesElements != null)
            {
                AssertionConsumerServices = ReadAcsService(assertionConsumerServicesElements);
            }

            ReadArtifactResolutionService(xmlElement);

            ReadSingleLogoutService(xmlElement); 

            ReadNameIDFormat(xmlElement);

            return this;
        }

        protected IEnumerable<AssertionConsumerService> ReadAcsService(XmlNodeList acsElements) 
        {
            foreach (XmlNode singleLogoutServiceElement in acsElements)
            {
                yield return new AssertionConsumerService
                {
                    Binding = singleLogoutServiceElement.Attributes[SamlMetadataConstants.Message.Binding].GetValueOrNull<Uri>(),
                    Location = singleLogoutServiceElement.Attributes[SamlMetadataConstants.Message.Location].GetValueOrNull<Uri>(),
                    IsDefault = singleLogoutServiceElement.Attributes[SamlMetadataConstants.Message.IsDefault].GetValueOrNull<bool>(),
                    Index = singleLogoutServiceElement.Attributes[SamlMetadataConstants.Message.Index].GetValueOrNull<int>(),
                };
            }
        }
    }
}
