using System;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Metadata
{
    public class SingleSignOnService : EndpointType
    {
        const string elementName = SamlMetadataConstants.Message.SingleSignOnService;

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlMetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

    }
}