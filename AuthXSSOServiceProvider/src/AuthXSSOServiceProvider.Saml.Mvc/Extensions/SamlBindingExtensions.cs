using System.Text;
using System.Web.Mvc;

namespace AuthXSSOServiceProvider.Saml.Mvc
{
    public static class SamlBindingExtensions
    {
        public static ActionResult ToActionResult(this SamlRedirectBinding binding)
        {
            return new RedirectResult(binding.RedirectLocation.OriginalString);
        }

        public static ActionResult ToActionResult(this SamlPostBinding binding)
        {
            return new ContentResult
            {
                Content = binding.PostContent
            };
        }

        public static ActionResult ToActionResult(this SamlArtifactBinding binding)
        {
            return new RedirectResult(binding.RedirectLocation.OriginalString);
        }

        public static ActionResult ToActionResult(this SamlSoapEnvelope binding)
        {
            return new ContentResult
            {
                ContentType = "text/xml; charset=\"utf-8\"",
                ContentEncoding = Encoding.UTF8,
                Content = binding.SoapResponseXml
            };
        }

        public static ActionResult ToActionResult(this SamlMetadata metadata)
        {
            return new ContentResult
            {
                ContentType = "text/xml",
                ContentEncoding = Encoding.UTF8,
                Content = metadata.ToXml(),
            };
        }
    }
}
