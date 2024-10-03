using System;
using System.Collections.Generic;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Metadata
{
    public class LocalizedUriType
    {
        public LocalizedUriType(string uri)
        {
            Uri = uri;
        }
        public LocalizedUriType(Uri uri)
        {
            Uri = uri?.OriginalString;
        }

        public LocalizedUriType(string uri, string lang) : this(uri) 
        {
            Lang = lang;
        }
        public LocalizedUriType(Uri uri, string lang) : this(uri)
        {
            Lang = lang;
        }
        public string Lang { get; protected set; }

        public string Uri { get; protected set; }

        public XElement ToXElement(XName elementName)
        {
            var envelope = new XElement(elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            if (Lang != null)
            {
                yield return new XAttribute(XNamespace.Xml + SamlMetadataConstants.Message.Lang, Lang);
            }

            yield return new XText(Uri);
        }
    }
}