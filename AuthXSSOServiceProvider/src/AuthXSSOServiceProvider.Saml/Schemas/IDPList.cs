using System.Collections.Generic;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas
{
    public class IDPList
    {
        public const string elementName = SamlConstants.Message.IDPList;

        public IEnumerable<IDPEntry> IDPEntry { get; set; }

        public string GetComplete { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlConstants.ProtocolNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

         protected virtual IEnumerable<XObject> GetXContent()
         {
            if (GetComplete != null)
            {
                yield return new XElement(SamlConstants.Message.GetComplete, GetComplete);
            }

            if (IDPEntry != null)
            {   
                foreach (var entry in IDPEntry)
                {
                    yield return entry.ToXElement();
                }
            }
        }
    }
}