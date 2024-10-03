using System.Collections.Generic;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Metadata
{
    public class EncryptionMethodType
    {
        const string elementName = SamlMetadataConstants.Message.EncryptionMethod;
        public string Algorithm { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlMetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            if (Algorithm != null)
            {
                yield return new XElement(SamlMetadataConstants.MetadataNamespaceX + SamlMetadataConstants.Message.Algorithm, Algorithm);
            }
        }
    }
}
