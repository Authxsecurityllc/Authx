using System.Collections.Generic;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas
{
    public class Subject
    {
        const string elementName = SamlConstants.Message.Subject;

        public NameID NameID { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlConstants.AssertionNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected virtual IEnumerable<XObject> GetXContent()
        {
            if (NameID != null)
            {
                yield return NameID.ToXElement();
            }
        }
    }
}
