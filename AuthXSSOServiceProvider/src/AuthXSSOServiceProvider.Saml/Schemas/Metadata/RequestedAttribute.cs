using System;
using System.Collections.Generic;
using System.Xml.Linq;
using System.Xml.Schema;

namespace AuthXSSOServiceProvider.Saml.Schemas.Metadata
{
    public class RequestedAttribute
    {
        const string elementName = SamlMetadataConstants.Message.RequestedAttribute;

        public RequestedAttribute(string name, bool isRequired = true, string nameFormat = SamlMetadataConstants.AttributeNameFormat, string friendlyName = null)
        {
            Name = name;
            IsRequired = isRequired;
            NameFormat = nameFormat;
            FriendlyName = friendlyName;
        }

        public RequestedAttribute(string name, string attributeValue, bool isRequired = true, string nameFormat = SamlMetadataConstants.AttributeNameFormat, string friendlyName = null)
            : this(name, isRequired, nameFormat, friendlyName)
        {
            AttributeValue = attributeValue;
        }

        public string Name { get; protected set; }

        public bool IsRequired { get; protected set; }

        public string NameFormat { get; protected set; }

        public string FriendlyName { get; protected set; }

        public string AttributeValue { get; protected set; }

        public string AttributeValueType { get; set; } = "xs:string";

        public string AttributeValueDataTypeNamespace { get; set; } = XmlSchema.Namespace;

        public string AttributeValueTypeNamespace { get; set; } = XmlSchema.InstanceNamespace;

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlMetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(SamlMetadataConstants.Message.Name, Name);
            yield return new XAttribute(SamlMetadataConstants.Message.NameFormat, NameFormat);
            yield return new XAttribute(SamlMetadataConstants.Message.IsRequired, IsRequired);

            if (!string.IsNullOrEmpty(FriendlyName))
            {
                yield return new XAttribute(SamlMetadataConstants.Message.FriendlyName, FriendlyName);
            }

            if (AttributeValue != null) 
            {
                var attribVal = new XElement(SamlMetadataConstants.SamlAssertionNamespaceX + SamlMetadataConstants.Message.AttributeValue) 
                {
                    Value = AttributeValue
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
