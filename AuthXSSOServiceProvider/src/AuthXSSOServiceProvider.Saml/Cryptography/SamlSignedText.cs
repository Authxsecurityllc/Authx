using System;
using System.Security.Cryptography.X509Certificates;

namespace AuthXSSOServiceProvider.Saml.Cryptography
{
    public class SamlSignedText
    {
        public SamlSigner SamlSigner { get; protected set; }

        public SamlSignedText(X509Certificate2 certificate, string signatureAlgorithm)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            SamlSigner = new SamlSigner(certificate, signatureAlgorithm);
        }

        public byte[] SignData(byte[] input)
        {
            (var formatter, var hashAlgorithm) = SamlSigner.CreateFormatter();
            return formatter.CreateSignature(hashAlgorithm.ComputeHash(input));
        }

        internal bool CheckSignature(byte[] input, byte[] signature)
        {
            (var deformatter, var hashAlgorithm) = SamlSigner.CreateDeformatter();
            return deformatter.VerifySignature(hashAlgorithm.ComputeHash(input), signature);
        }
    }
}
