using System;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Metadata
{
    public class SingleLogoutService : EndpointType
    {
        const string elementName = SamlMetadataConstants.Message.SingleLogoutService;

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlMetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }
    }
}
