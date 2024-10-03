using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Metadata
{
    public class Organization
    {
        const string elementName = SamlMetadataConstants.Message.Organization;

        public Organization() { }

        public Organization(string name, string displayName, string url)
        {
            OrganizationNames = new[] { new LocalizedNameType(name) };
            OrganizationDisplayNames = new[] { new LocalizedNameType(displayName) }; ;
            OrganizationURLs = new[] { new LocalizedUriType(url) }; ;
        }

        public Organization(IEnumerable<LocalizedNameType> names, IEnumerable<LocalizedNameType> displayNames, IEnumerable<LocalizedUriType> urls)
        {
            OrganizationNames = names;
            OrganizationDisplayNames = displayNames;
            OrganizationURLs = urls;
        }
        public IEnumerable<LocalizedNameType> OrganizationNames { get; set; }
        public IEnumerable<LocalizedNameType> OrganizationDisplayNames { get; set; }
        public IEnumerable<LocalizedUriType> OrganizationURLs { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlMetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            if (OrganizationNames != null)
            {
                foreach (var name in OrganizationNames)
                {
                    yield return name.ToXElement(SamlMetadataConstants.MetadataNamespaceX + SamlMetadataConstants.Message.OrganizationName);
                }
            }

            if (OrganizationDisplayNames != null)
            {
                foreach (var displayName in OrganizationDisplayNames)
                {
                    yield return displayName.ToXElement(SamlMetadataConstants.MetadataNamespaceX + SamlMetadataConstants.Message.OrganizationDisplayName);
                }
            }

            if (OrganizationURLs != null)
            {
                foreach (var url in OrganizationURLs)
                {
                    yield return url.ToXElement(SamlMetadataConstants.MetadataNamespaceX + SamlMetadataConstants.Message.OrganizationURL);
                }
            }
        }
    }
}