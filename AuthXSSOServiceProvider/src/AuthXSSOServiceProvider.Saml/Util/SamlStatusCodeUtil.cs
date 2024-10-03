using AuthXSSOServiceProvider.Saml.Schemas;
using System.Collections.Generic;
using System.Linq;

namespace AuthXSSOServiceProvider.Saml.Util
{
    internal static class SamlStatusCodeUtil
    {
        static readonly IDictionary<string, SamlStatusCodes> toEnums = new Dictionary<string, SamlStatusCodes>()
        {
            { "urn:oasis:names:tc:SAML:2.0:status:Success", SamlStatusCodes.Success },
            { "urn:oasis:names:tc:SAML:2.0:status:Requester", SamlStatusCodes.Requester },
            { "urn:oasis:names:tc:SAML:2.0:status:Responder", SamlStatusCodes.Responder },
            { "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch", SamlStatusCodes.VersionMismatch },
            { "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed", SamlStatusCodes.AuthnFailed },
            { "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue", SamlStatusCodes.InvalidAttrNameOrValue },
            { "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy", SamlStatusCodes.InvalidNameIdPolicy },
            { "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext", SamlStatusCodes.NoAuthnContext },
            { "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP", SamlStatusCodes.NoAvailableIDP },
            { "urn:oasis:names:tc:SAML:2.0:status:NoPassive", SamlStatusCodes.NoPassive },
            { "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP", SamlStatusCodes.NoSupportedIDP },
            { "urn:oasis:names:tc:SAML:2.0:status:PartialLogout", SamlStatusCodes.PartialLogout },
            { "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded", SamlStatusCodes.ProxyCountExceeded },
            { "urn:oasis:names:tc:SAML:2.0:status:RequestDenied", SamlStatusCodes.RequestDenied },
            { "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported", SamlStatusCodes.RequestUnsupported },
            { "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated", SamlStatusCodes.RequestVersionDeprecated },
            { "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh", SamlStatusCodes.RequestVersionTooHigh },
            { "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow", SamlStatusCodes.RequestVersionTooLow },
            { "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized", SamlStatusCodes.ResourceNotRecognized },
            { "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses", SamlStatusCodes.TooManyResponses },
            { "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile", SamlStatusCodes.UnknownAttrProfile },
            { "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal", SamlStatusCodes.UnknownPrincipal },
            { "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding", SamlStatusCodes.UnsupportedBinding },
        };

        static readonly IDictionary<SamlStatusCodes, string> toStrings = toEnums.ToDictionary(kvp => kvp.Value, kvp => kvp.Key);

        public static SamlStatusCodes ToEnum(string value)
        {
            return toEnums[value];
        }

        public static string ToString(SamlStatusCodes value)
        {
            return toStrings[value];
        }
    }
}
