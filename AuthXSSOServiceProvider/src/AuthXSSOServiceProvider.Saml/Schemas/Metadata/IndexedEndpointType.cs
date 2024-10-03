using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Metadata
{
    public abstract class IndexedEndpointType : EndpointType
    {
        public int Index { get; set; }
        public bool? IsDefault { get; set; }

        protected override IEnumerable<XObject> GetXContent()
        {
            foreach (var item in base.GetXContent())
            {
                yield return item;
            }

            yield return new XAttribute(SamlMetadataConstants.Message.Index, Index);

            if (IsDefault.HasValue)
            {
                yield return new XAttribute(SamlMetadataConstants.Message.IsDefault, IsDefault);
            }
        }

        protected override internal EndpointType Read(XmlElement xmlElement)
        {
            base.Read(xmlElement);

            Index = xmlElement.Attributes[SamlMetadataConstants.Message.Index].GetValueOrNull<int>();
            IsDefault = xmlElement.Attributes[SamlMetadataConstants.Message.IsDefault].GetValueOrNull<bool?>();

            return this;
        }
    }
}
