
using System;
namespace AuthXSSOServiceProvider.Saml.Schemas
{
    public static class ConsentIdentifierTypes
    {
        public static Uri Unspecified = new Uri("urn:oasis:names:tc:SAML:2.0:consent:unspecified");

        public static Uri Obtained = new Uri("urn:oasis:names:tc:SAML:2.0:consent:obtained");

        public static Uri Prior = new Uri("urn:oasis:names:tc:SAML:2.0:consent:prior");

        public static Uri Implicit = new Uri("urn:oasis:names:tc:SAML:2.0:consent:current-implicit");

        public static Uri Explicit = new Uri("urn:oasis:names:tc:SAML:2.0:consent:current-explicit");

        public static Uri Unavailable = new Uri("urn:oasis:names:tc:SAML:2.0:consent:unavailable");

        public static Uri Inapplicable = new Uri("urn:oasis:names:tc:SAML:2.0:consent:inapplicable");
    }
}
