using System;
using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Metadata
{
    public abstract class EndpointType
    {
        public Uri Binding { get; set; }
        public Uri Location { get; set; }
        public Uri ResponseLocation { get; set; }

        protected virtual IEnumerable<XObject> GetXContent()
        {
            if (Binding != null)
            {
                yield return new XAttribute(SamlMetadataConstants.Message.Binding, Binding.OriginalString);
            }
            if (Location != null)
            {
                yield return new XAttribute(SamlMetadataConstants.Message.Location, Location.OriginalString);
            }
            if(ResponseLocation != null)
            {
                yield return new XAttribute(SamlMetadataConstants.Message.ResponseLocation, ResponseLocation.OriginalString);
            }            
        }

        protected virtual internal EndpointType Read(XmlElement xmlElement)
        {
            Binding = xmlElement.Attributes[SamlMetadataConstants.Message.Binding].GetValueOrNull<Uri>();
            Location = xmlElement.Attributes[SamlMetadataConstants.Message.Location].GetValueOrNull<Uri>();
            ResponseLocation = xmlElement.Attributes[SamlMetadataConstants.Message.ResponseLocation].GetValueOrNull<Uri>();            

            return this;
        }
    }
}
