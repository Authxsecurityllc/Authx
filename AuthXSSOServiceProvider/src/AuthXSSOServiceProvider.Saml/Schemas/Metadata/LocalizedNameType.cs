using System.Collections.Generic;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Metadata
{
    public class LocalizedNameType
    {
        public LocalizedNameType(string name)
        {
            Name = name;
        }

        public LocalizedNameType(string name, string lang) : this(name) 
        {
            Lang = lang;
        }
        public string Lang { get; protected set; }
        public string Name { get; protected set; }

        public XElement ToXElement(XName elementName)
        {
            var envelope = new XElement(elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            if (Lang != null)
            {
                yield return new XAttribute(XNamespace.Xml + SamlMetadataConstants.Message.Lang, Lang);
            }

            yield return new XText(Name);
        }
    }
}