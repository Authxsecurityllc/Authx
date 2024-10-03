using System.Collections.Generic;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas
{
    public class Scoping
    {
        public const string elementName = SamlConstants.Message.Scoping;

        public IDPList IDPList { get; set; }

        public IEnumerable<string> RequesterID { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlConstants.ProtocolNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected virtual IEnumerable<XObject> GetXContent()
        {
            if (RequesterID != null)
            {
                foreach (var item in RequesterID)
                {
                    yield return new XElement(SamlConstants.Message.RequesterID, item);
                }
            }

            if (IDPList != null)
            {   
                yield return IDPList.ToXElement();
            }
        }
    }
}