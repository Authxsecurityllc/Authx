using System.Collections.Generic;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Conditions
{
    public class AudienceRestriction : ICondition
    {
        const string elementName = SamlConstants.Message.AudienceRestriction;

        public List<Audience> Audiences { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlConstants.AssertionNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            if (Audiences != null)
            {
                foreach (var audience in Audiences)
                {
                    yield return audience.ToXElement();
                }
            }
        }
    }
}