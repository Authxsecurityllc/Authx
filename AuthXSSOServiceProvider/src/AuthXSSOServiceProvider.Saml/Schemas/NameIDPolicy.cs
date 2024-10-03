using System.Collections.Generic;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas
{
    public class NameIdPolicy
    {
        const string elementName = SamlConstants.Message.NameIdPolicy;

        public bool? AllowCreate { get; set; }

        public string Format { get; set; }

        public string SPNameQualifier { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlConstants.ProtocolNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected virtual IEnumerable<XObject> GetXContent()
        {
            if (AllowCreate.HasValue)
            {
                yield return new XAttribute(SamlConstants.Message.AllowCreate, AllowCreate);
            }

            if (!string.IsNullOrWhiteSpace(Format))
            {
                yield return new XAttribute(SamlConstants.Message.Format, Format);
            }

            if (!string.IsNullOrWhiteSpace(SPNameQualifier))
            {
                yield return new XAttribute(SamlConstants.Message.SpNameQualifier, SPNameQualifier);
            }
        }
    }
}
