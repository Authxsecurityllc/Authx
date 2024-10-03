using AuthXSSOServiceProvider.Saml.Schemas.Metadata;
using System.Xml;

namespace AuthXSSOServiceProvider.Saml
{
    public class SamlMetadata
    {
        public SamlMetadata(EntityDescriptor entityDescriptor)
        {
            EntityDescriptor = entityDescriptor;
        }
        public SamlMetadata(EntitiesDescriptor entitiesDescriptor)
        {
            EntitiesDescriptor = entitiesDescriptor;
        }
        public EntityDescriptor EntityDescriptor { get; protected set; }
        public EntitiesDescriptor EntitiesDescriptor { get; protected set; }
        public XmlDocument XmlDocument { get; protected set; }
        public string ToXml()
        {
            return XmlDocument != null ? XmlDocument.OuterXml : null;
        }
        public SamlMetadata CreateMetadata()
        {
            if (EntityDescriptor != null)
            {
                XmlDocument = EntityDescriptor.ToXmlDocument();
            }
            else
            {
                XmlDocument = EntitiesDescriptor.ToXmlDocument();
            }
            return this;
        }
    }
}
