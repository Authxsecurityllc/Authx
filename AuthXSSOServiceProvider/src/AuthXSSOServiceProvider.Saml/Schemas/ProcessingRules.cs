using System;

namespace AuthXSSOServiceProvider.Saml.Schemas
{
    public static class ProcessingRules
    {
        public static Uri User = new Uri("urn:oasis:names:tc:SAML:2.0:logout:user");

        public static Uri Admin = new Uri("urn:oasis:names:tc:SAML:2.0:logout:admin");
    }
}
