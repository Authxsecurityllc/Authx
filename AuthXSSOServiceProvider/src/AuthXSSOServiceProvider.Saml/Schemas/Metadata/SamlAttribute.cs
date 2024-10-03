using System.Collections.Generic;
using System.Xml.Linq;
using System.Xml.Schema;

namespace AuthXSSOServiceProvider.Saml.Schemas.Metadata
{
    public class SamlAttribute
    {
        const string elementName = SamlMetadataConstants.Message.Attribute;

        public SamlAttribute(string name, string nameFormat = SamlMetadataConstants.AttributeNameFormatUri, string friendlyName = null)
        {
            Name = name;
            NameFormat = nameFormat;
            FriendlyName = friendlyName;
        }

        public SamlAttribute(string name, IEnumerable<string> attributeValues, string nameFormat = SamlMetadataConstants.AttributeNameFormatUri, string friendlyName = null)
            : this(name, nameFormat, friendlyName)
        {
            AttributeValues = attributeValues;
        }

        public string Name { get; protected set; }

        public string NameFormat { get; protected set; }

        public string FriendlyName { get; protected set; }

        public IEnumerable<string> AttributeValues { get; protected set; }

        public string AttributeValueType { get; set; } = "xs:string";

        public string AttributeValueDataTypeNamespace { get; set; } = XmlSchema.Namespace;

        public string AttributeValueTypeNamespace { get; set; } = XmlSchema.InstanceNamespace;

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlMetadataConstants.SamlAssertionNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(SamlMetadataConstants.Message.Name, Name);
            yield return new XAttribute(SamlMetadataConstants.Message.NameFormat, NameFormat);
            if (!string.IsNullOrEmpty(FriendlyName))
            {
                yield return new XAttribute(SamlMetadataConstants.Message.FriendlyName, FriendlyName);
            }

            if (AttributeValues != null)
            {
                foreach (var attributeValue in AttributeValues)
                {
                    var attribVal = new XElement(SamlMetadataConstants.SamlAssertionNamespaceX + SamlMetadataConstants.Message.AttributeValue)
                    {
                        Value = attributeValue
                    };
                    attribVal.Add(new XAttribute(SamlMetadataConstants.SamlAssertionNamespaceNameX, SamlMetadataConstants.SamlAssertionNamespace));
                    if (!string.IsNullOrWhiteSpace(AttributeValueType) && TryGetAttributeValueTypeNamespaceName(out var attributeValueTypeNamespaceName) && !string.IsNullOrWhiteSpace(AttributeValueDataTypeNamespace) && !string.IsNullOrWhiteSpace(AttributeValueTypeNamespace))
                    {
                        attribVal.Add(new XAttribute(XNamespace.Xmlns + attributeValueTypeNamespaceName, AttributeValueDataTypeNamespace));
                        attribVal.Add(new XAttribute(SamlMetadataConstants.XsiInstanceNamespaceNameX, AttributeValueTypeNamespace));
                        attribVal.Add(new XAttribute(XNamespace.Get(AttributeValueTypeNamespace) + SamlMetadataConstants.Message.Type, AttributeValueType));
                    }
                    yield return attribVal;
                }
            }
        }

        private bool TryGetAttributeValueTypeNamespaceName(out string attributeValueTypeNamespaceName)
        {
            var splitValues = AttributeValueType?.Split(':');
            if (splitValues?.Length == 2)
            {
                attributeValueTypeNamespaceName = splitValues[0];
                return true;
            }

            attributeValueTypeNamespaceName = null;
            return false;
        }
    }
}
