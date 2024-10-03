using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Conditions
{
    public class OneTimeUse : ICondition
    {
        const string elementName = SamlConstants.Message.OneTimeUse;

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlConstants.AssertionNamespaceX + elementName);

            return envelope;
        }
    }
}