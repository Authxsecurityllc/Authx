using Microsoft.AspNetCore.Mvc;

namespace AuthXSSOServiceProvider.Saml.MvcCore
{
    public static class SamlBindingExtensions
    {
        public static IActionResult ToActionResult(this SamlRedirectBinding binding)
        {
            return new RedirectResult(binding.RedirectLocation.OriginalString);
        }

        public static IActionResult ToActionResult(this SamlPostBinding binding)
        {
            return new ContentResult
            {
                ContentType = "text/html",
                Content = binding.PostContent
            };
        }

        public static IActionResult ToActionResult(this SamlArtifactBinding binding)
        {
            return new RedirectResult(binding.RedirectLocation.OriginalString);
        }

        public static IActionResult ToActionResult(this SamlSoapEnvelope binding)
        {
            return new ContentResult
            {
                ContentType = "text/xml; charset=\"utf-8\"",                
                Content = binding.SoapResponseXml
            };
        }

        public static IActionResult ToActionResult(this SamlMetadata metadata)
        {
            return new ContentResult
            {
                ContentType = "text/xml",
                Content = metadata.ToXml(),
            };
        }
    }
}
