using System;
using System.Linq;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Metadata
{
    public class Extensions
    {
        const string elementName = SamlConstants.Message.Extensions;
        XElement envelope = new XElement(SamlMetadataConstants.MetadataNamespaceX + elementName);

        public XElement Element
        {
            get
            {
                return envelope;
            }
            internal set
            {
                envelope = value;
            }
        }

        public XElement ToXElement()
        {
            if (!envelope.Name.Namespace.Equals(SamlMetadataConstants.MetadataNamespaceX))
            {
                throw new Exception($"Invalid Extensions namespace. Required namespace '{SamlMetadataConstants.MetadataNamespaceX}'.");
            }
            if (!envelope.Name.LocalName.Equals(elementName))
            {
                throw new Exception($"Invalid Extensions name. Required name '{elementName}'.");
            }

            if (envelope.Elements().Count() <= 0)
            {
                throw new Exception($"Extensions is empty.");
            }

            return envelope;
        }
    }
}
