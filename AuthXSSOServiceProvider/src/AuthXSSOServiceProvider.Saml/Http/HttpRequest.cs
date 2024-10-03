using System.Collections.Specialized;

namespace AuthXSSOServiceProvider.Saml.Http
{
    public class HttpRequest
    {
        public string Method { get; set; }

        public SamlBinding Binding { get; set; }
        public string QueryString { get; set; }
        public NameValueCollection Query { get; set; }
        public NameValueCollection Form { get; set; }
        public string Body { get; set; }
    }
}
