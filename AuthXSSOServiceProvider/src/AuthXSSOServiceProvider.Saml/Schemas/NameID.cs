using System.Collections.Generic;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas
{
    public class NameID
    {
        const string elementName = SamlConstants.Message.NameId;

        public string ID { get; set; }

        public string Format { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlConstants.AssertionNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            if (!string.IsNullOrWhiteSpace(Format))
            {
                yield return new XAttribute(SamlConstants.Message.Format, Format);
            }

            yield return new XText(ID);
        }
    }
}
