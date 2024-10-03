using AuthXSSOServiceProvider.Saml.Http;
using AuthXSSOServiceProvider.Saml.Schemas;
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace AuthXSSOServiceProvider.Saml
{
    public abstract class SamlBinding
    {
        public XmlDocument XmlDocument { get; protected set; }

        public string SignatureAlgorithm { get; protected set; }

        public string XmlCanonicalizationMethod { get; protected set; }
        public string RelayState { get; set; }

        public SamlBinding()
        { }

        protected virtual void BindInternal(SamlRequest SamlRequestResponse, bool createXml = true)
        {
            if (SamlRequestResponse == null)
                throw new ArgumentNullException(nameof(SamlRequestResponse));

            if (SamlRequestResponse.Config == null)
                throw new ArgumentNullException("SamlRequestResponse.Config");

            if (SamlRequestResponse.Config.SigningCertificate != null)
            {
                if (SamlRequestResponse.Config.SigningCertificate.GetSamlRSAPrivateKey() == null)
                {
                    throw new ArgumentException("No RSA Private Key present in Signing Certificate or missing private key.");
                }
            }

            if (createXml)
            {
                XmlDocument = SamlRequestResponse.ToXml();
            }
        }

        internal void ApplyBinding(SamlRequest SamlRequestResponse, string messageName)
        {
            BindInternal(SamlRequestResponse, messageName);
        }

        protected abstract void BindInternal(SamlRequest SamlRequestResponse, string messageName);

        public SamlRequest Unbind(HttpRequest request, SamlRequest SamlRequest)
        {
            return UnbindInternal(request, SamlRequest, SamlConstants.Message.SamlRequest);
        }

        public SamlResponse Unbind(HttpRequest request, SamlResponse SamlResponse)
        {
            return UnbindInternal(request, SamlResponse, SamlConstants.Message.SamlResponse) as SamlResponse;
        }

        public SamlArtifactResolve Unbind(HttpRequest request, SamlArtifactResolve SamlArtifactResolve)
        {
            return UnbindInternal(request, SamlArtifactResolve, SamlConstants.Message.SamlArt) as SamlArtifactResolve;
        }

        protected SamlRequest UnbindInternal(HttpRequest request, SamlRequest SamlRequestResponse)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));

            if (SamlRequestResponse == null)
                throw new ArgumentNullException(nameof(SamlRequestResponse));

            if (SamlRequestResponse.Config == null)
                throw new ArgumentNullException("SamlRequestResponse.Config");

            SetSignatureValidationCertificates(SamlRequestResponse);

            return SamlRequestResponse;
        }

        protected void SetSignatureValidationCertificates(SamlRequest SamlRequestResponse)
        {
            if (SamlRequestResponse.SignatureValidationCertificates == null || SamlRequestResponse.SignatureValidationCertificates.Count() < 1)
                SamlRequestResponse.SignatureValidationCertificates = SamlRequestResponse.Config.SignatureValidationCertificates;
            if (SamlRequestResponse.SignatureAlgorithm == null)
                SamlRequestResponse.SignatureAlgorithm = SamlRequestResponse.Config.SignatureAlgorithm;
            if (SamlRequestResponse.XmlCanonicalizationMethod == null)
                SamlRequestResponse.XmlCanonicalizationMethod = SamlRequestResponse.Config.XmlCanonicalizationMethod;

            if (SamlRequestResponse.SignatureValidationCertificates != null && SamlRequestResponse.SignatureValidationCertificates.Count(c => c.GetRSAPublicKey() == null) > 0)
                throw new ArgumentException("No RSA Public Key present in at least Signature Validation Certificate.");
        }

        protected abstract SamlRequest UnbindInternal(HttpRequest request, SamlRequest SamlRequestResponse, string messageName);

        public SamlRequest ReadSamlRequest(HttpRequest request, SamlRequest SamlRequest)
        {
            return Read(request, SamlRequest, SamlConstants.Message.SamlRequest, false, false);
        }

        public SamlRequest ReadSamlResponse(HttpRequest request, SamlResponse SamlResponse)
        {
            return Read(request, SamlResponse, SamlConstants.Message.SamlResponse, false, false);
        }

        public SamlRequest ReadSamlResponse(HttpRequest request, SamlArtifactResolve SamlArtifactResolve)
        {
            return Read(request, SamlArtifactResolve, SamlConstants.Message.SamlArt, false, false);
        }


        protected abstract SamlRequest Read(HttpRequest request, SamlRequest SamlRequestResponse, string messageName, bool validate, bool detectReplayedTokens);

        public bool IsRequest(HttpRequest request)
        {
            return IsRequestResponseInternal(request, SamlConstants.Message.SamlRequest);
        }

        public bool IsResponse(HttpRequest request)
        {
            return IsRequestResponseInternal(request, SamlConstants.Message.SamlResponse);
        }

        protected abstract bool IsRequestResponseInternal(HttpRequest request, string messageName);
    }
}
