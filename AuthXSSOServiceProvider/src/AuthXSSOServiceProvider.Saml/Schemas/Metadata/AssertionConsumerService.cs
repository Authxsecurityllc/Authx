using System;
using System.Collections.Generic;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Metadata
{

    public class AssertionConsumerService
    {
        const string elementName = SamlMetadataConstants.Message.AssertionConsumerService;


        public Uri Binding { get; set; }

        public Uri Location { get; set; }
        public bool IsDefault { get; set; } = true;
        public int Index { get; set; }

        public XElement ToXElement(int index)
        {
            var envelope = new XElement(SamlMetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent(index));

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent(int index)
        {
            yield return new XAttribute(SamlMetadataConstants.Message.Binding, Binding.OriginalString);
            yield return new XAttribute(SamlMetadataConstants.Message.Location, Location.OriginalString);
            yield return new XAttribute(SamlMetadataConstants.Message.Index, index);
            if (IsDefault)
            {
                yield return new XAttribute(SamlMetadataConstants.Message.IsDefault, IsDefault);
            }
        }
    }
}
