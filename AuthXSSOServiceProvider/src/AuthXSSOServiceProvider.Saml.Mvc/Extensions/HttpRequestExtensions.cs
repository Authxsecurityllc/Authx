using AuthXSSOServiceProvider.Saml.Schemas;
using System.Web;
using System;
using System.IO;
using System.Linq;

namespace AuthXSSOServiceProvider.Saml.Mvc
{
    public static class HttpRequestExtensions
    {
        public static Http.HttpRequest ToGenericHttpRequest(this HttpRequestBase request, bool readBodyAsString = false, bool validate = false)
        {
            var samlHttpRequest = new Http.HttpRequest
            {
                Method = request.HttpMethod,
                QueryString = request.Url.Query,
                Query = request.QueryString,
                Body = ReadBody(request, readBodyAsString)
            };

            if ("POST".Equals(request.HttpMethod, StringComparison.InvariantCultureIgnoreCase))
            {
                samlHttpRequest.Form = request.Form;
                samlHttpRequest.Binding = new SamlPostBinding();
            }
            else
            {
                if (samlHttpRequest.Query.AllKeys.Contains(SamlConstants.Message.SamlArt))
                {
                    samlHttpRequest.Binding = new SamlArtifactBinding();
                }
                else
                {
                    samlHttpRequest.Binding = new SamlRedirectBinding();
                }
            }

            if (validate)
            {
                var length = 0;
                if (!string.IsNullOrEmpty(samlHttpRequest.QueryString))
                {
                    length += samlHttpRequest.QueryString.Length;
                }
                if (readBodyAsString)
                {
                    if (!string.IsNullOrEmpty(samlHttpRequest.Body))
                    {
                        length += samlHttpRequest.Body.Length;
                    }
                }
                else
                {
                    if (samlHttpRequest.Form != null)
                    {
                        foreach (string item in samlHttpRequest.Form)
                        {
                            if (!string.IsNullOrEmpty(item))
                            {
                                length += item.Length;
                            }
                        }
                    }
                }
                if (length > SamlConstants.RequestResponseMaxLength)
                {
                    throw new SamlRequestException($"Invalid SAML 2.0 request/response with a length of {length}, max length {SamlConstants.RequestResponseMaxLength}.");
                }
            }
            return samlHttpRequest;
        }

        private static string ReadBody(HttpRequestBase request, bool readBodyAsString)
        {
            if (!readBodyAsString)
            {
                return null;
            }

            using (var reader = new StreamReader(request.InputStream))
            {
                return reader.ReadToEnd();
            }
        }
    }
}
