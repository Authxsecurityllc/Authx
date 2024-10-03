#if !NETFULL
using Microsoft.IdentityModel.Tokens;
#endif
using System;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas
{
    public static class SamlConstants
    {
#if !NETFULL
        public const int RequestResponseMaxLength = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;
#else
        public const int RequestResponseMaxLength = 1024 * 250;        
#endif

        public const string AuthenticationScheme = "Saml";

        public const string VersionNumber = "2.0";

        public const string DateTimeFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";

        public static readonly Uri SamlBearerToken = new Uri("urn:oasis:names:tc:SAML:2.0:cm:bearer");

        internal static readonly Uri AssertionNamespace = new Uri("urn:oasis:names:tc:SAML:2.0:assertion");
        public static readonly XNamespace AssertionNamespaceX = XNamespace.Get(AssertionNamespace.OriginalString);
        public static readonly XName AssertionNamespaceNameX = XNamespace.Xmlns + "saml";

        internal static readonly Uri ProtocolNamespace = new Uri("urn:oasis:names:tc:SAML:2.0:protocol");
        public static readonly XNamespace ProtocolNamespaceX = XNamespace.Get(ProtocolNamespace.OriginalString);
        public static readonly XName ProtocolNamespaceNameX = XNamespace.Xmlns + "samlp";

        public static readonly Uri SoapEnvironmentNamespace = new Uri("http://schemas.xmlsoap.org/soap/envelope/");
        public static readonly XNamespace SoapEnvironmentNamespaceX = XNamespace.Get(SoapEnvironmentNamespace.OriginalString);
        public static readonly XName SoapEnvironmentNamespaceNameX = XNamespace.Xmlns + "SOAP-ENV";

        public static class Message
        {
            public const string SamlResponse = "SAMLResponse";

            public const string SamlRequest = "SAMLRequest";

            public const string SamlArt = "SAMLart";

            public const string RelayState = "RelayState";

            public const string Assertion = "Assertion";

            public const string EncryptedAssertion = "EncryptedAssertion";

            public const string Protocol = "Protocol";

            public const string AuthnRequest = "AuthnRequest";

            public const string AuthnResponse = "Response";

            public const string LogoutRequest = "LogoutRequest";

            public const string LogoutResponse = "LogoutResponse";

            public const string ArtifactResolve = "ArtifactResolve";

            public const string ArtifactResponse = "ArtifactResponse";

            internal const string Artifact = "Artifact";

            internal const string Id = "ID";

            internal const string Version = "Version";

            internal const string IssueInstant = "IssueInstant";

            internal const string Consent = "Consent";

            internal const string Destination = "Destination";

            internal const string Signature = "Signature";

            internal const string SigAlg = "SigAlg";

            internal const string Issuer = "Issuer";

            internal const string Status = "Status";

            internal const string StatusCode = "StatusCode";

            internal const string StatusMessage = "StatusMessage";

            internal const string Value = "Value";

            internal const string AssertionConsumerServiceIndex = "AssertionConsumerServiceIndex";

            internal const string AssertionConsumerServiceURL = "AssertionConsumerServiceURL";

            internal const string AttributeConsumingServiceIndex = "AttributeConsumingServiceIndex";

            internal const string ProtocolBinding = "ProtocolBinding";

            internal const string RequestedAuthnContext = "RequestedAuthnContext";

            internal const string Comparison = "Comparison";

            internal const string AuthnContextClassRef = "AuthnContextClassRef";

            internal const string ForceAuthn = "ForceAuthn";

            internal const string IsPassive = "IsPassive";

            internal const string NameId = "NameID";

            internal const string SessionIndex = "SessionIndex";

            internal const string Format = "Format";

            internal const string NotOnOrAfter = "NotOnOrAfter";

            internal const string NotBefore = "NotBefore";

            internal const string Reason = "Reason";
            
            internal const string NameIdPolicy = "NameIDPolicy";

            internal const string AllowCreate = "AllowCreate";

            internal const string NameQualifier = "NameQualifier";

            internal const string SpNameQualifier = "SPNameQualifier";
            
            internal const string Extensions = "Extensions";

            internal const string InResponseTo = "InResponseTo";

            internal const string Conditions = "Conditions";

            internal const string AudienceRestriction = "AudienceRestriction";

            internal const string Audience = "Audience";

            internal const string Subject = "Subject";

            internal const string SubjectConfirmation = "SubjectConfirmation";

            internal const string SubjectConfirmationData = "SubjectConfirmationData";

            internal const string OneTimeUse = "OneTimeUse";

            internal const string ProxyRestriction = "ProxyRestriction";

            internal const string Count = "Count";

            internal const string Envelope = "Envelope";

            internal const string Body = "Body";

            internal const string Scoping = "Scoping";

            internal const string RequesterID = "RequesterID";

            internal const string IDPList = "IDPList";

            internal const string IDPEntry = "IDPEntry";

            internal const string ProviderID = "ProviderID";

            internal const string Name = "Name";

            internal const string Loc = "Loc";

            internal const string GetComplete = "GetComplete";
            
            internal const string ProviderName = "ProviderName";

        }
    }
}
