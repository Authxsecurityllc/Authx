using System;

namespace AuthXSSOServiceProvider.Saml.Schemas
{
    public static class NameIdentifierFormats
    {
        public static Uri Unspecified = new Uri("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

        public static Uri Email = new Uri("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");


        public static Uri Entity = new Uri("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");

        public static Uri Persistent = new Uri("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");

        public static Uri Transient = new Uri("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
    }
}
