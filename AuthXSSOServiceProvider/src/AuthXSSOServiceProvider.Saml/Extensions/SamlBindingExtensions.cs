using AuthXSSOServiceProvider.Saml.Schemas;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace AuthXSSOServiceProvider.Saml
{
    public static class SamlBindingExtensions
    {
        public static T Bind<T>(this T binding, SamlRequest SamlRequest) where T : SamlBinding
        {
            binding.ApplyBinding(SamlRequest, SamlConstants.Message.SamlRequest);
            return binding;
        }

        public static T Bind<T>(this T binding, SamlResponse SamlResponse) where T : SamlBinding
        {
            binding.ApplyBinding(SamlResponse, SamlConstants.Message.SamlResponse);
            return binding;
        }

        public static T Bind<T>(this T binding, SamlArtifactResolve SamlArtifactResolve) where T : SamlBinding
        {
            binding.ApplyBinding(SamlArtifactResolve, SamlConstants.Message.SamlArt);
            return binding;
        }
        public static string SetRelayStateQuery<T>(this T SamlBinding, Dictionary<string, string> elements)
            where T : SamlBinding
        {
            if(elements == null)
            {
                throw new ArgumentNullException(nameof(elements));
            }

            SamlBinding.RelayState = string.Join("&", ElementsToStrings(elements));
            return SamlBinding.RelayState;
        }

        private static IEnumerable<string> ElementsToStrings(Dictionary<string, string> elements)
        {
            foreach (var element in elements)
            {
                yield return string.Join("=", element.Key, Uri.EscapeDataString(element.Value));
            }
        }
        public static Dictionary<string, string> GetRelayStateQuery<T>(this T SamlBinding)
            where T : SamlBinding
        {
            Dictionary<string, string> elements = new Dictionary<string,string>();
            if (string.IsNullOrWhiteSpace(SamlBinding.RelayState))
            {
                return elements;
            }

            var match = Regex.Match(SamlBinding.RelayState, @"(?<key>[^=^&]+)=(?<value>[^=^&]*)(&(?<key>[^=^&]+)=(?<value>[^=^&]*))*");
            if (!match.Success || match.Groups["key"] == null || match.Groups["value"] == null)
            {
                throw new InvalidDataException("Invalid Relay State Query.");
            }

            for (var i = 0; i < match.Groups["key"].Captures.Count; i++)
            {
                elements.Add(match.Groups["key"].Captures[i].Value, Uri.UnescapeDataString(match.Groups["value"].Captures[i].Value));
            }
            return elements;
        }
    }
}
