using AuthXSSOServiceProvider.Saml.Schemas;
using System;

namespace AuthXSSOServiceProvider.Saml.Cryptography
{
    public static class SignatureAlgorithm
    {
        public static void ValidateAlgorithm(string signatureAlgorithm)
        {            
            if (SamlSecurityAlgorithms.RsaSha1Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return;
            }
            else if (SamlSecurityAlgorithms.RsaSha256Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return;
            }
            else if (SamlSecurityAlgorithms.RsaSha384Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return;
            }
            else if (SamlSecurityAlgorithms.RsaSha512Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return;
            }
            else if (SamlSecurityAlgorithms.RsaPssSha256Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return;
            }
            throw new NotSupportedException($"Only SHA1 ({SamlSecurityAlgorithms.RsaSha1Signature}), SHA256 ({SamlSecurityAlgorithms.RsaSha256Signature}), SHA384 ({SamlSecurityAlgorithms.RsaSha384Signature}), SHA512 ({SamlSecurityAlgorithms.RsaSha512Signature}) and SHA256 RSA MGF1 ({SamlSecurityAlgorithms.RsaPssSha256Signature}) is supported.");

        }

        public static string DigestMethod(string signatureAlgorithm)
        {
            if (SamlSecurityAlgorithms.RsaSha1Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return SamlSecurityAlgorithms.Sha1Digest;
            }
            else if (SamlSecurityAlgorithms.RsaSha256Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return SamlSecurityAlgorithms.Sha256Digest;
            }
            else if (SamlSecurityAlgorithms.RsaSha384Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return SamlSecurityAlgorithms.Sha384Digest;
            }
            else if (SamlSecurityAlgorithms.RsaSha512Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return SamlSecurityAlgorithms.Sha512Digest;
            }
            else if (SamlSecurityAlgorithms.RsaPssSha256Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return SamlSecurityAlgorithms.Sha256Digest;
            }
            else
            {
                ValidateAlgorithm(signatureAlgorithm);
                throw new InvalidOperationException();
            }            
        }
    }
}
