namespace AuthXSSOServiceProvider.Saml.Schemas
{
    public static class SamlSecurityAlgorithms
    {
        public const string Sha1Digest = "http://www.w3.org/2000/09/xmldsig#sha1";
        public const string RsaSha1Signature = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";       

        public const string Sha256Digest = "http://www.w3.org/2001/04/xmlenc#sha256";
        public const string RsaSha256Signature = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

        public const string Sha384Digest = "http://www.w3.org/2001/04/xmldsig-more#sha384";
        public const string RsaSha384Signature = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";

        public const string Sha512Digest = "http://www.w3.org/2001/04/xmlenc#sha512";
        public const string RsaSha512Signature = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
        public const string RsaPssSha256Signature = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
    }
}
