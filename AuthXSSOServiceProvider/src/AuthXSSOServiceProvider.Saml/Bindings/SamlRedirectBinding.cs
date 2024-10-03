using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Xml;
using AuthXSSOServiceProvider.Saml.Schemas;
using AuthXSSOServiceProvider.Saml.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AuthXSSOServiceProvider.Saml.Util;
using AuthXSSOServiceProvider.Saml.Http;

namespace AuthXSSOServiceProvider.Saml
{
    public class SamlRedirectBinding : SamlBinding
    {
        public Uri RedirectLocation { get; protected set; }

        public string Signature { get; protected set; }

        protected override void BindInternal(SamlRequest SamlRequestResponse, string messageName)
        {
            base.BindInternal(SamlRequestResponse);

            if (SamlRequestResponse is SamlAuthnResponse)
            {
                if (SamlRequestResponse.Config.AuthnResponseSignType != SamlAuthnResponseSignTypes.SignResponse)
                {
                    throw new InvalidSamlBindingException($"Redirect binding does not support {SamlRequestResponse.Config.AuthnResponseSignType}, only {nameof(SamlAuthnResponseSignTypes.SignResponse)} is supported.");
                }
                if(SamlRequestResponse.Config.EncryptionCertificate != null)
                {
                    throw new InvalidSamlBindingException("Redirect binding does not support authentication response encryption; this feature is only available with post binding.");
                }
            }

            if ((!(SamlRequestResponse is SamlAuthnRequest) || SamlRequestResponse.Config.SignAuthnRequest) && SamlRequestResponse.Config.SigningCertificate != null)
            {
                Cryptography.SignatureAlgorithm.ValidateAlgorithm(SamlRequestResponse.Config.SignatureAlgorithm);
                Cryptography.XmlCanonicalizationMethod.ValidateCanonicalizationMethod(SamlRequestResponse.Config.XmlCanonicalizationMethod);
                SignatureAlgorithm = SamlRequestResponse.Config.SignatureAlgorithm;
                XmlCanonicalizationMethod = SamlRequestResponse.Config.XmlCanonicalizationMethod;
            }

            var requestQueryString = string.Join("&", RequestQueryString(SamlRequestResponse, messageName));
            if ((!(SamlRequestResponse is SamlAuthnRequest) || SamlRequestResponse.Config.SignAuthnRequest) && SamlRequestResponse.Config.SigningCertificate != null)
            {
                requestQueryString = SigneQueryString(requestQueryString, SamlRequestResponse.Config.SigningCertificate);
            }

            RedirectLocation = new Uri(string.Join(SamlRequestResponse.Destination.OriginalString.Contains('?') ? "&" : "?", SamlRequestResponse.Destination.OriginalString, requestQueryString));
        }

        private string SigneQueryString(string queryString, X509Certificate2 signingCertificate)
        {
            var SamlSigned = new SamlSignedText(signingCertificate, SignatureAlgorithm);
            Signature = Convert.ToBase64String(SamlSigned.SignData(Encoding.UTF8.GetBytes(queryString)));

            return string.Join("&", queryString, string.Join("=", SamlConstants.Message.Signature, Uri.EscapeDataString(Signature)));
        }

        private IEnumerable<string> RequestQueryString(SamlRequest SamlRequestResponse, string messageName)
        {
            yield return string.Join("=", messageName, Uri.EscapeDataString(CompressRequest()));

            if (!string.IsNullOrWhiteSpace(RelayState))
            {
                yield return string.Join("=", SamlConstants.Message.RelayState, Uri.EscapeDataString(RelayState));
            }

            if ((!(SamlRequestResponse is SamlAuthnRequest) || SamlRequestResponse.Config.SignAuthnRequest) && SamlRequestResponse.Config.SigningCertificate != null)
            {
                yield return string.Join("=", SamlConstants.Message.SigAlg, Uri.EscapeDataString(SignatureAlgorithm));
            }
        }

        private string CompressRequest()
        {
            using (var compressedStream = new MemoryStream())
            using (var deflateStream = new DeflateStream(compressedStream, CompressionMode.Compress))
            {
                using (var originalStream = new StreamWriter(deflateStream))
                {
                    originalStream.Write(XmlDocument.OuterXml);
                }

                return Convert.ToBase64String(compressedStream.ToArray());
            }
        }

        protected override SamlRequest UnbindInternal(HttpRequest request, SamlRequest SamlRequestResponse, string messageName)
        {
            UnbindInternal(request, SamlRequestResponse);

            if (!"GET".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
                throw new InvalidSamlBindingException("Not redirect binding (HTTP GET).");

            if (!request.Query.AllKeys.Contains(messageName))
                throw new SamlBindingException("HTTP Query String does not contain " + messageName);

            if ((!(SamlRequestResponse is SamlAuthnRequest) || SamlRequestResponse.Config.SignAuthnRequest) &&
                SamlRequestResponse.SignatureValidationCertificates != null && SamlRequestResponse.SignatureValidationCertificates.Count() > 0)
            {
                if (!request.Query.AllKeys.Contains(SamlConstants.Message.Signature))
                    throw new SamlBindingException("HTTP Query String does not contain " + SamlConstants.Message.Signature);

                if (!request.Query.AllKeys.Contains(SamlConstants.Message.SigAlg))
                    throw new SamlBindingException("HTTP Query String does not contain " + SamlConstants.Message.SigAlg);
            }

            if (request.Query.AllKeys.Contains(SamlConstants.Message.RelayState))
            {
                RelayState = request.Query[SamlConstants.Message.RelayState];
            }

            if ((!(SamlRequestResponse is SamlAuthnRequest) || SamlRequestResponse.Config.SignAuthnRequest) &&
                SamlRequestResponse.SignatureValidationCertificates != null && SamlRequestResponse.SignatureValidationCertificates.Count() > 0)
            {
                var actualSignatureAlgorithm = request.Query[SamlConstants.Message.SigAlg];
                if (SamlRequestResponse.SignatureAlgorithm == null)
                {
                    SamlRequestResponse.SignatureAlgorithm = actualSignatureAlgorithm;
                }
                else if (!SamlRequestResponse.SignatureAlgorithm.Equals(actualSignatureAlgorithm, StringComparison.InvariantCulture))
                {
                    throw new Exception($"Signature Algorithm do not match. Expected algorithm {SamlRequestResponse.SignatureAlgorithm} actual algorithm {actualSignatureAlgorithm}");
                }
                if (SamlRequestResponse.XmlCanonicalizationMethod == null)
                {
                    SamlRequestResponse.XmlCanonicalizationMethod = SamlRequestResponse.Config.XmlCanonicalizationMethod;
                }
                Cryptography.SignatureAlgorithm.ValidateAlgorithm(SamlRequestResponse.SignatureAlgorithm);
                Cryptography.XmlCanonicalizationMethod.ValidateCanonicalizationMethod(SamlRequestResponse.XmlCanonicalizationMethod);
                SignatureAlgorithm = SamlRequestResponse.SignatureAlgorithm;
                XmlCanonicalizationMethod = SamlRequestResponse.XmlCanonicalizationMethod;

                Signature = request.Query[SamlConstants.Message.Signature];
                ValidateQueryStringSignature(SamlRequestResponse, request.QueryString, messageName, Convert.FromBase64String(Signature), SamlRequestResponse.SignatureValidationCertificates);
            }

            return Read(request, SamlRequestResponse, messageName, false, true);
        }

        protected override SamlRequest Read(HttpRequest request, SamlRequest SamlRequestResponse, string messageName, bool validate, bool detectReplayedTokens)
        {
            if (!"GET".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
                throw new InvalidSamlBindingException("Not redirect binding (HTTP GET).");

            if (!request.Query.AllKeys.Contains(messageName))
                throw new SamlBindingException("HTTP Query String does not contain " + messageName);

            if (request.Query.AllKeys.Contains(SamlConstants.Message.RelayState))
            {
                RelayState = request.Query[SamlConstants.Message.RelayState];
            }

            SamlRequestResponse.Read(DecompressResponse(request.Query[messageName]), validate, detectReplayedTokens);
            XmlDocument = SamlRequestResponse.XmlDocument;
            return SamlRequestResponse;
        }

        protected override bool IsRequestResponseInternal(HttpRequest request, string messageName)
        {
            return (request.Query?.AllKeys?.Contains(messageName)).GetValueOrDefault(false);
        }

        private void ValidateQueryStringSignature(SamlRequest SamlRequestResponse, string queryString, string messageName, byte[] signatureValue, IEnumerable<X509Certificate2> signatureValidationCertificates)
        {
            foreach (var signatureValidationCertificate in signatureValidationCertificates)
            {
                var SamlSign = new SamlSignedText(signatureValidationCertificate, SignatureAlgorithm);
                if (SamlSign.CheckSignature(Encoding.UTF8.GetBytes(new RawSamlQueryString(queryString, messageName).SignedQueryString), signatureValue))
                {
                    // Check if certificate used to sign is valid
                    SamlRequestResponse.IdentityConfiguration.CertificateValidator.Validate(signatureValidationCertificate);

                    // Signature is valid.
                    return;
                }
            }
            throw new InvalidSignatureException("Signature is invalid.");
        }

        private string DecompressResponse(string value)
        {
            using (var originalStream = new MemoryStream(Convert.FromBase64String(value)))
            using (var decompressedStream = new MemoryStream())
            {
                using (var deflateStream = new DeflateStream(originalStream, CompressionMode.Decompress))
                {
                    deflateStream.CopyTo(decompressedStream);
                }
                return Encoding.UTF8.GetString(decompressedStream.ToArray());
            }
        }
    }
}
