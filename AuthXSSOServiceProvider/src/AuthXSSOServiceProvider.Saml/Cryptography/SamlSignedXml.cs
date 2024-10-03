using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace AuthXSSOServiceProvider.Saml.Cryptography
{
    public class SamlSignedXml : SignedXml
    {
        public XmlElement Element { get; protected set; }
        public SamlSigner SamlSigner { get; protected set; }
        public string CanonicalizationMethod { get; protected set; }

        public SamlSignedXml(XmlElement element, X509Certificate2 certificate, string signatureAlgorithm, string canonicalizationMethod) : base(element)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));
            if (signatureAlgorithm == null) throw new ArgumentNullException(nameof(signatureAlgorithm));
            if (canonicalizationMethod == null) throw new ArgumentNullException(nameof(canonicalizationMethod));

            Element = element;
            CanonicalizationMethod = canonicalizationMethod;
            SamlSigner = new SamlSigner(certificate, signatureAlgorithm);
        }

        public void ComputeSignature(X509IncludeOption includeOption, string id)
        {
            var reference = new Reference("#" + id);
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.DigestMethod = SignatureAlgorithm.DigestMethod(SamlSigner.SignatureAlgorithm);
            reference.AddTransform(XmlCanonicalizationMethod.GetTransform(CanonicalizationMethod));
            SignedInfo.CanonicalizationMethod = CanonicalizationMethod;

            AddReference(reference);
            SignedInfo.SignatureMethod = SamlSigner.SignatureAlgorithm;
            SigningKey = SamlSigner.Certificate.GetSamlRSAPrivateKey();
            ComputeSignature();

            KeyInfo = new KeyInfo();
            KeyInfo.AddClause(new KeyInfoX509Data(SamlSigner.Certificate, includeOption));
        }

        public new bool CheckSignature()
        {
            if (SignedInfo.References.Count != 1)
            {
                throw new InvalidSignatureException("Invalid XML signature reference.");
            }

            if (SignedInfo.CanonicalizationMethod != CanonicalizationMethod)
            {
                throw new InvalidSignatureException($"Invalid canonicalization method {SignedInfo.CanonicalizationMethod} used in signature.");
            }

            if (SignedInfo.SignatureMethod != SamlSigner.SignatureAlgorithm)
            {
                throw new InvalidSignatureException($"Invalid signature method {SignedInfo.SignatureMethod} used in signature.");
            }

            var reference = SignedInfo.References[0] as Reference;
            AssertReferenceValid(reference);

            return CheckSignature(SamlSigner.Certificate.GetRSAPublicKey());
        }

        private void AssertReferenceValid(Reference reference)
        {
            var referenceId = reference.Uri.Substring(1);
            if (Element != GetIdElement(Element.OwnerDocument, referenceId))
            {
                throw new InvalidSignatureException("XML signature reference do not refer to the root element.");
            }

            AssertTransformChainValid(reference.TransformChain);
        }

        private void AssertTransformChainValid(TransformChain transformChain)
        {
            foreach (Transform transform in transformChain)
            {
                var algorithm = transform.Algorithm;
                if (algorithm != XmlDsigEnvelopedSignatureTransformUrl && algorithm != CanonicalizationMethod)
                {
                    throw new InvalidSignatureException($"Invalid transform method {algorithm} used in signature.");
                }
            }
        }
    }
}