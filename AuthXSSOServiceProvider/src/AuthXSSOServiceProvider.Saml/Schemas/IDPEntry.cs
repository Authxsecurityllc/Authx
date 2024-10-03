using System.Collections.Generic;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas
{
    public class IDPEntry
    {
        public const string elementName = SamlConstants.Message.IDPEntry;

        public string ProviderID { get; set; }

        public string Name { get; set; }

        public string Loc { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlConstants.ProtocolNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

         protected virtual IEnumerable<XObject> GetXContent()
         {
            if (ProviderID != null)
            {
                yield return new XAttribute(SamlConstants.Message.ProviderID, ProviderID);
            }

            if (Name != null)
            {
                yield return new XAttribute(SamlConstants.Message.Name, Name);
            }

            if (Loc != null)
            {
                yield return new XAttribute(SamlConstants.Message.Loc, Loc);
            }
        }
    }
}