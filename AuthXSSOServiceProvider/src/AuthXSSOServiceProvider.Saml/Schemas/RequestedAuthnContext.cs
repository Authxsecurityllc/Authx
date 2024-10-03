using System.Collections.Generic;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas
{
    public class RequestedAuthnContext
    {
        const string elementName = SamlConstants.Message.RequestedAuthnContext;

        public AuthnContextComparisonTypes? Comparison { get; set; }

        public IEnumerable<string> AuthnContextClassRef { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlConstants.ProtocolNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected virtual IEnumerable<XObject> GetXContent()
        {
            if (Comparison.HasValue)
            {
                yield return new XAttribute(SamlConstants.Message.Comparison, Comparison.ToString().ToLowerInvariant());
            }

            foreach (var item in AuthnContextClassRef)
            {
                yield return new XElement(SamlConstants.AssertionNamespaceX + SamlConstants.Message.AuthnContextClassRef, item);
            }
        }
    }
}
