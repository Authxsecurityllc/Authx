using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using AuthXSSOServiceProvider.Saml.Schemas;
using AuthXSSOServiceProvider.Saml.Http;

namespace AuthXSSOServiceProvider.Saml
{
    public class SamlArtifactBinding : SamlBinding
    {
        public X509IncludeOption CertificateIncludeOption { get; set; }

        public Uri RedirectLocation { get; protected set; }

        public SamlArtifactBinding()
        {
            CertificateIncludeOption = X509IncludeOption.EndCertOnly;
        }

        protected override void BindInternal(SamlRequest SamlRequest, string messageName)
        {
            if (!(SamlRequest is SamlArtifactResolve SamlArtifactResolve))
                throw new ArgumentException("Only SamlArtifactResolve is supported");

            base.BindInternal(SamlArtifactResolve, false);

            SamlArtifactResolve.CreateArtifact();

            var requestQueryString = string.Join("&", RequestQueryString(SamlArtifactResolve, messageName));
            RedirectLocation = new Uri(string.Join(SamlArtifactResolve.Destination.OriginalString.Contains('?') ? "&" : "?", SamlArtifactResolve.Destination.OriginalString, requestQueryString));
        }

        private IEnumerable<string> RequestQueryString(SamlArtifactResolve SamlArtifactResolve, string messageName)
        {
            yield return string.Join("=", messageName, Uri.EscapeDataString(SamlArtifactResolve.Artifact));

            if (!string.IsNullOrWhiteSpace(RelayState))
            {
                yield return string.Join("=", SamlConstants.Message.RelayState, Uri.EscapeDataString(RelayState));
            }
        }

        protected override SamlRequest UnbindInternal(HttpRequest request, SamlRequest SamlRequest, string messageName)
        {
            UnbindInternal(request, SamlRequest);

            return Read(request, SamlRequest, messageName, true, true);
        }

        protected override SamlRequest Read(HttpRequest request, SamlRequest SamlRequest, string messageName, bool validate, bool detectReplayedTokens)
        {
            if (!(SamlRequest is SamlArtifactResolve SamlArtifactResolve))
                throw new ArgumentException("Only SamlArtifactResolve is supported");

            if ("GET".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
            {
                return ReadGet(request, SamlArtifactResolve, messageName, validate, detectReplayedTokens);
            }
            else if ("POST".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
            {
                return ReadPost(request, SamlArtifactResolve, messageName, validate, detectReplayedTokens);
            }
            else
                throw new InvalidSamlBindingException("Not HTTP GET or HTTP POST Method.");
        }

        private SamlRequest ReadGet(HttpRequest request, SamlArtifactResolve SamlArtifactResolve, string messageName, bool validate, bool detectReplayedTokens)
        {
            if (!request.Query.AllKeys.Contains(messageName))
                throw new SamlBindingException("HTTP Query String does not contain " + messageName);

            if (request.Query.AllKeys.Contains(SamlConstants.Message.RelayState))
            {
                RelayState = request.Query[SamlConstants.Message.RelayState];
            }

            SamlArtifactResolve.Artifact = request.Query[messageName];
            if (validate)
            {
                SamlArtifactResolve.ValidateArtifact();
            }
            return SamlArtifactResolve;
        }

        private SamlRequest ReadPost(HttpRequest request, SamlArtifactResolve SamlArtifactResolve, string messageName, bool validate, bool detectReplayedTokens)
        {
            if (!request.Form.AllKeys.Contains(messageName))
                throw new SamlBindingException("HTTP Form does not contain " + messageName);

            if (request.Form.AllKeys.Contains(SamlConstants.Message.RelayState))
            {
                RelayState = request.Form[SamlConstants.Message.RelayState];
            }

            SamlArtifactResolve.Artifact = request.Form[messageName];
            if (validate)
            {
                SamlArtifactResolve.ValidateArtifact();
            }
            return SamlArtifactResolve;
        }

        protected override bool IsRequestResponseInternal(HttpRequest request, string messageName)
        {
            if ("GET".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
            {
                return (request.Query?.AllKeys?.Contains(messageName)).GetValueOrDefault(false);
            }
            else if ("POST".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
            {
                return (request.Form?.AllKeys?.Contains(messageName)).GetValueOrDefault(false);
            }
            else
            {
                throw new InvalidSamlBindingException("Not HTTP GET or HTTP POST Method.");
            }
        }
    }
}
