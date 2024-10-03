using AuthXSSOServiceProvider.Saml.Configuration;
using AuthXSSOServiceProvider.Saml.Http;
using AuthXSSOServiceProvider.Saml.Schemas;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml
{
    public class SamlSoapEnvelope : SamlBinding
    {
        public string SoapResponseXml { get; set; }

        protected override void BindInternal(SamlRequest SamlRequest, string messageName)
        {
            if (!(SamlRequest is SamlArtifactResponse))
                throw new ArgumentException("Only Saml ArtifactResponse is supported");

            BindInternal(SamlRequest);

            SoapResponseXml = ToSoapXml();
        }

        protected override SamlRequest UnbindInternal(HttpRequest request, SamlRequest SamlRequest, string messageName)
        {
            UnbindInternal(request, SamlRequest);

            return Read(request, SamlRequest, messageName, true, true);
        }

        protected override SamlRequest Read(HttpRequest request, SamlRequest SamlRequest, string messageName, bool validate, bool detectReplayedTokens)
        {
            if (!(SamlRequest is SamlArtifactResolve SamlArtifactResolve))
                throw new ArgumentException("Only Saml ArtifactResolve is supported");

            SamlArtifactResolve.Read(FromSoapXml(request.Body), validate, detectReplayedTokens);
            XmlDocument = SamlArtifactResolve.XmlDocument;
            return SamlArtifactResolve;
        }

        protected override bool IsRequestResponseInternal(HttpRequest request, string messageName)
        {
            throw new NotSupportedException();
        }

        public virtual async Task<SamlArtifactResponse> ResolveAsync(
#if NET || NETCORE
            IHttpClientFactory httpClientFactory,
#else
            HttpClient httpClient,
# endif
            SamlArtifactResolve SamlArtifactResolve, SamlRequest SamlRequest, CancellationToken? cancellationToken = null
#if NET || NETCORE
            , string httpClientName = null) 
        {
            var httpClient = string.IsNullOrEmpty(httpClientName) ? httpClientFactory.CreateClient() : httpClientFactory.CreateClient(httpClientName);
#else
        )
        {
#endif
            if (SamlArtifactResolve.Config.ArtifactResolutionService is null || SamlArtifactResolve.Config.ArtifactResolutionService.Location is null)
            {
                throw new SamlConfigurationException("The ArtifactResolutionService is required to be configured.");
            }
            var artifactDestination = SamlArtifactResolve.Config.ArtifactResolutionService.Location;
            SamlArtifactResolve.Destination = artifactDestination;
            XmlDocument = SamlArtifactResolve.ToXml();

            var content = new StringContent(ToSoapXml(), Encoding.UTF8, "text/xml");
            content.Headers.Add("SOAPAction", "\"http://www.oasis-open.org/committees/security\"");

            using (var response = cancellationToken.HasValue ? await httpClient.PostAsync(artifactDestination, content, cancellationToken.Value) : await httpClient.PostAsync(artifactDestination, content))
            {
                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
#if NET
                        var result = cancellationToken.HasValue ? await response.Content.ReadAsStringAsync(cancellationToken.Value) : await response.Content.ReadAsStringAsync();
#else
                        var result = await response.Content.ReadAsStringAsync();
#endif
                        var SamlArtifactResponse = new SamlArtifactResponse(SamlArtifactResolve.Config, SamlRequest);
                        SetSignatureValidationCertificates(SamlArtifactResponse);
                        var xml = FromSoapXml(result);
                        SamlArtifactResponse.Read(xml, false, false); 
                        if (SamlArtifactResponse.Status == SamlStatusCodes.Success && 
                            (SamlRequest is SamlAuthnResponse SamlAuthnResponse ? SamlAuthnResponse.Status == SamlStatusCodes.Success : true))
                        {
                            SamlArtifactResponse.Read(xml, SamlArtifactResponse.SignatureValidationCertificates?.Count() > 0, true);
                        }
                        return SamlArtifactResponse;

                    default:
                        throw new Exception($"Error, Status Code OK expected. StatusCode '{response.StatusCode}'. Artifact resolve destination '{artifactDestination?.OriginalString}'.");
                }
            }
        }

        protected virtual string ToSoapXml()
        {
            var envelope = new XElement(SamlConstants.SoapEnvironmentNamespaceX + SamlConstants.Message.Envelope);

            envelope.Add(GetXContent());

            return envelope.ToString(SaveOptions.DisableFormatting);
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(SamlConstants.SoapEnvironmentNamespaceNameX, SamlConstants.SoapEnvironmentNamespace.OriginalString);
            yield return new XElement(SamlConstants.SoapEnvironmentNamespaceX + SamlConstants.Message.Body, XmlDocument.ToXDocument().Root);
        }

        protected virtual string FromSoapXml(string xml)
        {
            var xmlDoc = xml.ToXmlDocument();

            var bodyList = GetNodesByLocalName(xmlDoc.DocumentElement, "Body");
            if (bodyList.Count != 1)
            {
                throw new Exception("Body element count is more than one.");
            }

            var faultBody = GetNodeByLocalName(bodyList[0], "Fault");
            if (faultBody != null)
            {
                var faultCode = GetNodeByLocalName(faultBody, "faultcode");
                var faultString = GetNodeByLocalName(faultBody, "faultstring");
                throw new SamlRequestException("SAML 2.0 Artifact SOAP error: " + faultCode + "\n" + faultString);
            }

            return bodyList[0].InnerXml;
        }

        private XmlNodeList GetNodesByLocalName(XmlNode xe, string localName)
        {
            return xe.SelectNodes(string.Format("//*[local-name()='{0}']", localName));
        }

        private XmlNode GetNodeByLocalName(XmlNode xe, string localName)
        {
            return xe.SelectSingleNode(string.Format("//*[local-name()='{0}']", localName));
        }
    }
}