using System.Collections.Generic;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Conditions
{
    public class Audience
    {
        const string elementName = SamlConstants.Message.Audience;

        public string Uri { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlConstants.AssertionNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            if (!string.IsNullOrEmpty(Uri))
            {
                yield return new XText(Uri);
            }
        }
    }
}