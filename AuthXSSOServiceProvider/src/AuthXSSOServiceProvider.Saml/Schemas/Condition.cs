using System;
using System.Collections.Generic;
using System.Globalization;
using System.Xml.Linq;
using AuthXSSOServiceProvider.Saml.Schemas.Conditions;

namespace AuthXSSOServiceProvider.Saml.Schemas
{
    public class Condition
    {
        public const string elementName = SamlConstants.Message.Conditions;

        public IEnumerable<ICondition> Items { get; set; }

        public DateTimeOffset? NotOnOrAfter { get; set; }

        public DateTimeOffset? NotBefore { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlConstants.AssertionNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected virtual IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(SamlConstants.AssertionNamespaceNameX, SamlConstants.AssertionNamespaceX);
            if (NotOnOrAfter.HasValue)
            {
                yield return new XAttribute(SamlConstants.Message.NotOnOrAfter, NotOnOrAfter.Value.UtcDateTime.ToString(SamlConstants.DateTimeFormat, CultureInfo.InvariantCulture));
            }

            if (NotBefore.HasValue)
            {
                yield return new XAttribute(SamlConstants.Message.NotBefore, NotBefore.Value.UtcDateTime.ToString(SamlConstants.DateTimeFormat, CultureInfo.InvariantCulture));
            }

            if (Items != null)
            {
                foreach (var condition in Items)
                {
                    yield return condition.ToXElement();
                }
            }
        }
    }
}