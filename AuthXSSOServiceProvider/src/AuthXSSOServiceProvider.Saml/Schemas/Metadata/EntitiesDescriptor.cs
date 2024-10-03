using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
#if NETFULL
using System.IdentityModel.Tokens;
#else
using Microsoft.IdentityModel.Tokens.Saml2;
#endif

namespace AuthXSSOServiceProvider.Saml.Schemas.Metadata
{
    public class EntitiesDescriptor
    {
        const string elementName = SamlMetadataConstants.Message.EntitiesDescriptor;

        public SamlConfiguration Config { get; protected set; }
        public Saml2Id Id { get; protected set; }
        public string IdAsString
        {
            get { return Id?.Value; }
        }
        public string Name { get; protected set; }
        public int? ValidUntil { get; set; }
        public X509Certificate2 MetadataSigningCertificate { get; protected set; }
        public X509IncludeOption CertificateIncludeOption { get; set; }
        public IEnumerable<EntityDescriptor> EntityDescriptorList { get; protected set; }
        public Extensions Extensions { get; set; }

        public EntitiesDescriptor()
        { }

        public EntitiesDescriptor(SamlConfiguration config, IEnumerable<EntityDescriptor> entitiesDescriptor, string name = null, bool signMetadata = true) : this()
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            Config = config;
            Id = new Saml2Id();
            Name = name;
            EntityDescriptorList = entitiesDescriptor;
            if (signMetadata)
            {
                MetadataSigningCertificate = config.SigningCertificate;
                CertificateIncludeOption = X509IncludeOption.EndCertOnly;
            }
        }

        public XmlDocument ToXmlDocument()
        {
            var envelope = new XElement(SamlMetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());
            var xmlDocument = envelope.ToXmlDocument();
            if(MetadataSigningCertificate != null)
            {
                xmlDocument.SignDocument(MetadataSigningCertificate, Config.SignatureAlgorithm, Config.XmlCanonicalizationMethod, CertificateIncludeOption, IdAsString);
            }
            return xmlDocument;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(SamlMetadataConstants.Message.Id, IdAsString);
            if(Name != null)
            {
                yield return new XAttribute(SamlMetadataConstants.Message.Name, Name);
            }
            if (ValidUntil.HasValue)
            {
                yield return new XAttribute(SamlMetadataConstants.Message.ValidUntil, DateTimeOffset.UtcNow.AddDays(ValidUntil.Value).UtcDateTime.ToString(SamlConstants.DateTimeFormat, CultureInfo.InvariantCulture));
            }
            yield return new XAttribute(SamlMetadataConstants.MetadataNamespaceNameX, SamlMetadataConstants.MetadataNamespace);

            if (Extensions != null) 
            {
                yield return Extensions.ToXElement();
            }
            
            if (EntityDescriptorList != null)
            {
                foreach( var entityDescriptor in EntityDescriptorList)
                {
                    yield return entityDescriptor.ToXElement();
                }
            }
        }
    }
}
