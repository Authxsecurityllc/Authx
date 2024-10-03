using System.Collections.Generic;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Metadata
{
    public class ContactPerson
    {
        const string elementName = SamlMetadataConstants.Message.ContactPerson;

        public ContactPerson(ContactTypes contactType)
        {
            ContactType = contactType;
        }
        public ContactTypes ContactType { get; protected set; }
        public string Company { get; set; }
        public string GivenName { get; set; }
        public string SurName { get; set; }
        public string EmailAddress { get; set; }
        public string TelephoneNumber { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(SamlMetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(SamlMetadataConstants.Message.ContactType, ContactType.ToString().ToLowerInvariant());

            if (Company != null)
            {
                yield return new XElement(SamlMetadataConstants.MetadataNamespaceX + SamlMetadataConstants.Message.Company, Company);
            }

            if (GivenName != null)
            {
                yield return new XElement(SamlMetadataConstants.MetadataNamespaceX + SamlMetadataConstants.Message.GivenName, GivenName);
            }

            if (SurName != null)
            {
                yield return new XElement(SamlMetadataConstants.MetadataNamespaceX + SamlMetadataConstants.Message.SurName, SurName);
            }

            if (EmailAddress != null)
            {
                yield return new XElement(SamlMetadataConstants.MetadataNamespaceX + SamlMetadataConstants.Message.EmailAddress, EmailAddress);
            }

            if (TelephoneNumber != null)
            {
                yield return new XElement(SamlMetadataConstants.MetadataNamespaceX + SamlMetadataConstants.Message.TelephoneNumber, TelephoneNumber);
            }
        }
    }
}
