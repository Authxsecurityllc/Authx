using System;
using System.Collections.Generic;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Metadata
{
    public class AttributeConsumingService
    {
        const string elementName = SamlMetadataConstants.Message.AttributeConsumingService;

        [Obsolete("The ServiceName method is deprecated. Please use ServiceNames which is a list of service names.")]
        public LocalizedNameType ServiceName { get; set; }
        public int Index { get; set; } = 0;
        public IEnumerable<LocalizedNameType> ServiceNames { get; set; }
        public IEnumerable<RequestedAttribute> RequestedAttributes { get; set; }
        public bool IsDefault { get; set; } = true;

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlMetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(SamlMetadataConstants.Message.Index, Index);
            if (IsDefault)
            {
                yield return new XAttribute(SamlMetadataConstants.Message.IsDefault, IsDefault);
            }

            if (ServiceNames != null)
            {
                foreach (var serviceName in ServiceNames)
                {
                    yield return serviceName.ToXElement(SamlMetadataConstants.MetadataNamespaceX + SamlMetadataConstants.Message.ServiceName);
                }
            }
            else if (ServiceName != null)
            {
                yield return ServiceName.ToXElement(SamlMetadataConstants.MetadataNamespaceX + SamlMetadataConstants.Message.ServiceName);
            }

            if (RequestedAttributes != null)
            {
                foreach (var reqAtt in RequestedAttributes)
                {
                    yield return reqAtt.ToXElement();
                } 
            }
        }
    }
}
