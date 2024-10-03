using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using AuthXSSOServiceProvider.Saml.Schemas;
using AuthXSSOServiceProvider.Saml.Http;
using System.Net;

namespace AuthXSSOServiceProvider.Saml
{
    public class SamlPostBinding : SamlBinding
    {
        public X509IncludeOption CertificateIncludeOption { get; set; }

        public string PostContent { get; set; }

        public SamlPostBinding()
        {
            CertificateIncludeOption = X509IncludeOption.EndCertOnly;
        }

        protected override void BindInternal(SamlRequest SamlRequestResponse, string messageName)
        {
            BindInternal(SamlRequestResponse);

            if (SamlRequestResponse is SamlAuthnResponse)
            {
                if (SamlRequestResponse.Config.AuthnResponseSignType != SamlAuthnResponseSignTypes.SignResponse)
                {
                    (SamlRequestResponse as SamlAuthnResponse).SignAuthnResponseAssertion(CertificateIncludeOption);
                }
                if (SamlRequestResponse.Config.EncryptionCertificate != null)
                {
                    (SamlRequestResponse as SamlAuthnResponse).EncryptMessage();
                }
            }

            if ((!(SamlRequestResponse is SamlAuthnRequest) || SamlRequestResponse.Config.SignAuthnRequest) && SamlRequestResponse.Config.SigningCertificate != null)
            {
                if (!(SamlRequestResponse is SamlAuthnResponse && SamlRequestResponse.Config.AuthnResponseSignType == SamlAuthnResponseSignTypes.SignAssertion))
                {
                    Cryptography.SignatureAlgorithm.ValidateAlgorithm(SamlRequestResponse.Config.SignatureAlgorithm);
                    Cryptography.XmlCanonicalizationMethod.ValidateCanonicalizationMethod(SamlRequestResponse.Config.XmlCanonicalizationMethod);
                    XmlDocument = XmlDocument.SignDocument(SamlRequestResponse.Config.SigningCertificate, SamlRequestResponse.Config.SignatureAlgorithm, SamlRequestResponse.Config.XmlCanonicalizationMethod, CertificateIncludeOption, SamlRequestResponse.IdAsString);
                }
            }

            PostContent = string.Concat(HtmlPostPage(SamlRequestResponse.Destination, messageName));
        }

        private IEnumerable<string> HtmlPostPage(Uri destination, string messageName)
        {
            yield return string.Format(
@"<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""utf-8"" />
    <meta http-equiv=""X-UA-Compatible"" content=""IE=edge"" />
    <title>SAML 2.0</title>
</head>
<body onload=""document.forms[0].submit()"">
    <noscript>
        <p>
            <strong>Note:</strong> Since your browser does not support JavaScript, 
            you must press the Continue button once to proceed.
        </p>
    </noscript>
    <form action=""{0}"" method=""post"">
        <div>", destination);

            yield return string.Format(
@"<input type=""hidden"" name=""{0}"" value=""{1}""/>", messageName, Convert.ToBase64String(Encoding.UTF8.GetBytes(XmlDocument.OuterXml)));

            if (!string.IsNullOrWhiteSpace(RelayState))
            {
                yield return string.Format(
@"<input type=""hidden"" name=""{0}"" value=""{1}""/>", SamlConstants.Message.RelayState, WebUtility.HtmlEncode(RelayState));
            }

            yield return
@"</div>
        <noscript>
            <div>
                <input type=""submit"" value=""Continue""/>
            </div>
        </noscript>
    </form>
</body>
</html>";
        }

        protected override SamlRequest UnbindInternal(HttpRequest request, SamlRequest SamlRequestResponse, string messageName)
        {
            UnbindInternal(request, SamlRequestResponse);

            return Read(request, SamlRequestResponse, messageName, true, true);
        }

        protected override SamlRequest Read(HttpRequest request, SamlRequest SamlRequestResponse, string messageName, bool validate, bool detectReplayedTokens)
        {
            if (!"POST".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
                throw new InvalidSamlBindingException("Not POST binding (HTTP POST).");

            if (!request.Form.AllKeys.Contains(messageName))
                throw new SamlBindingException("HTTP Form does not contain " + messageName);

            if (request.Form.AllKeys.Contains(SamlConstants.Message.RelayState))
            {
                RelayState = request.Form[SamlConstants.Message.RelayState];
            }

            SamlRequestResponse.Read(Encoding.UTF8.GetString(Convert.FromBase64String(request.Form[messageName])), validate, detectReplayedTokens);
            XmlDocument = SamlRequestResponse.XmlDocument;
            return SamlRequestResponse;
        }

        protected override bool IsRequestResponseInternal(HttpRequest request, string messageName)
        {
            return (request.Form?.AllKeys?.Contains(messageName)).GetValueOrDefault(false);
        }
    }
}
