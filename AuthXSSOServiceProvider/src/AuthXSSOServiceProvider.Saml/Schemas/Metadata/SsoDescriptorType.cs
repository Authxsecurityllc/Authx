using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Metadata
{
    public abstract class SsoDescriptorType
    {
        protected internal string protocolSupportEnumeration = SamlConstants.ProtocolNamespace.OriginalString;
        public X509IncludeOption CertificateIncludeOption { get; set; } = X509IncludeOption.EndCertOnly;
        public IEnumerable<X509Certificate2> SigningCertificates { get; set; }
        public IEnumerable<X509Certificate2> EncryptionCertificates { get; set; }
        public IEnumerable<EncryptionMethodType> EncryptionMethods { get; set; }
        public IEnumerable<ArtifactResolutionService> ArtifactResolutionServices { get; set; }
        public IEnumerable<SingleLogoutService> SingleLogoutServices { get; set; }
        public IEnumerable<Uri> NameIDFormats { get; set; }
        public Extensions Extensions { get; set; }
        public void SetDefaultEncryptionMethods()
        {
            EncryptionMethods = new[] { new EncryptionMethodType { Algorithm = EncryptedXml.XmlEncAES256Url }, new EncryptionMethodType { Algorithm = EncryptedXml.XmlEncRSAOAEPUrl } };
        }

        protected XObject KeyDescriptor(X509Certificate2 certificate, string keyType, IEnumerable<EncryptionMethodType> encryptionMethods = null)
        {
            var keyinfo = new KeyInfo();
            keyinfo.AddClause(new KeyInfoName(Convert.ToBase64String(certificate.GetCertHash())));
            keyinfo.AddClause(new KeyInfoX509Data(certificate, CertificateIncludeOption));

            var keyDescriptorElement = new XElement(SamlMetadataConstants.MetadataNamespaceX + SamlMetadataConstants.Message.KeyDescriptor,
                new XAttribute(SamlMetadataConstants.Message.Use, keyType),
                XElement.Parse(keyinfo.GetXml().OuterXml));

            if (keyType == SamlMetadataConstants.KeyTypes.Encryption && encryptionMethods?.Count() > 0)
            {
                foreach(var encryptionMethod in encryptionMethods)
                {
                    keyDescriptorElement.Add(new XElement(SamlMetadataConstants.MetadataNamespaceX + SamlMetadataConstants.Message.EncryptionMethod,
                        new XAttribute(SamlMetadataConstants.Message.Algorithm, encryptionMethod.Algorithm)));
                }
            }

            return keyDescriptorElement;
        }

        protected void ReadKeyDescriptors(XmlElement xmlElement)
        {
            var signingKeyDescriptorElements = xmlElement.SelectNodes($"*[local-name()='{SamlMetadataConstants.Message.KeyDescriptor}'][contains(@use,'{SamlMetadataConstants.KeyTypes.Signing}') or not(@use)]");
            if (signingKeyDescriptorElements != null)
            {
                SigningCertificates = ReadKeyDescriptorElements(signingKeyDescriptorElements);
            }

            var encryptionKeyDescriptorElements = xmlElement.SelectNodes($"*[local-name()='{SamlMetadataConstants.Message.KeyDescriptor}'][contains(@use,'{SamlMetadataConstants.KeyTypes.Encryption}') or not(@use)]");
            if (encryptionKeyDescriptorElements != null)
            {
                EncryptionCertificates = ReadKeyDescriptorElements(encryptionKeyDescriptorElements);
            }
        }

        protected void ReadSingleLogoutService(XmlElement xmlElement)
        {
            var singleLogoutServiceElements = xmlElement.SelectNodes($"*[local-name()='{SamlMetadataConstants.Message.SingleLogoutService}']");
            if (singleLogoutServiceElements != null)
            {
                SingleLogoutServices = ReadServices<SingleLogoutService>(singleLogoutServiceElements);
            }
        }

        protected void ReadArtifactResolutionService(XmlElement xmlElement)
        {
            var artifactResolutionElements = xmlElement.SelectNodes($"*[local-name()='{SamlMetadataConstants.Message.ArtifactResolutionService}']");
            if (artifactResolutionElements != null)
            {
                ArtifactResolutionServices = ReadServices<ArtifactResolutionService>(artifactResolutionElements);
            }
        }

        protected void ReadNameIDFormat(XmlElement xmlElement)
        {
            var nameIDFormatElements = xmlElement.SelectNodes($"*[local-name()='{SamlMetadataConstants.Message.NameIDFormat}']");
            if (nameIDFormatElements != null)
            {
                NameIDFormats = ReadNameIDFormatElements(nameIDFormatElements);
            }
        }

        protected IEnumerable<Uri> ReadNameIDFormatElements(XmlNodeList nameIDFormatElements)
        {
            foreach (XmlNode nameIDFormatElement in nameIDFormatElements)
            {
                yield return new Uri(nameIDFormatElement.InnerText);
            }
        }

        protected IEnumerable<X509Certificate2> ReadKeyDescriptorElements(XmlNodeList keyDescriptorElements)
        {
            foreach (XmlElement keyDescriptorElement in keyDescriptorElements)
            {
                var keyInfoElement = keyDescriptorElement.SelectSingleNode($"*[local-name()='{SamlMetadataConstants.Message.KeyInfo}']") as XmlElement;
                if (keyInfoElement != null)
                {
                    var keyInfo = new KeyInfo();
                    keyInfo.LoadXml(keyInfoElement);
                    var keyInfoEnumerator = keyInfo.GetEnumerator();
                    while (keyInfoEnumerator.MoveNext())
                    {
                        var keyInfoX509Data = keyInfoEnumerator.Current as KeyInfoX509Data;
                        if (keyInfoX509Data != null)
                        {
                            foreach (var certificate in keyInfoX509Data.Certificates)
                            {
                                if (certificate is X509Certificate2)
                                {
                                    yield return certificate as X509Certificate2;
                                }
                            }
                        }
                    }
                }
            }
        }

        protected IEnumerable<T> ReadServices<T>(XmlNodeList serviceElements) where T : EndpointType, new()
        {
            foreach (XmlNode serviceElement in serviceElements)
            {
                var endpoint = new T
                {
                    Binding = serviceElement.Attributes[SamlMetadataConstants.Message.Binding].GetValueOrNull<Uri>(),
                    Location = serviceElement.Attributes[SamlMetadataConstants.Message.Location].GetValueOrNull<Uri>(),
                    ResponseLocation = serviceElement.Attributes[SamlMetadataConstants.Message.ResponseLocation].GetValueOrNull<Uri>()
                };

                if (endpoint is IndexedEndpointType indexedEndpoint)
                {
                    indexedEndpoint.Index = serviceElement.Attributes[SamlMetadataConstants.Message.Index].GetValueOrNull<int>();
                    indexedEndpoint.IsDefault = serviceElement.Attributes[SamlMetadataConstants.Message.IsDefault].GetValueOrNull<bool>();
                }

                yield return endpoint;
            }
        }
    }
}
