using System;

namespace AuthXSSOServiceProvider.Saml.Schemas
{
    public static class ProtocolBindings
    {
        public static Uri HttpRedirect= new Uri("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");

        public static Uri HttpPost= new Uri("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

        public static Uri HttpArtifact = new Uri("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact");

        public static Uri ArtifactSoap = new Uri("urn:oasis:names:tc:SAML:2.0:bindings:SOAP");
    }
}
