
namespace AuthXSSOServiceProvider.Saml.Schemas
{
    public enum SamlStatusCodes
    {
        Success,
        Requester,
        Responder,
        VersionMismatch,
        AuthnFailed,
        InvalidAttrNameOrValue,
        InvalidNameIdPolicy,
        NoAuthnContext,
        NoAvailableIDP,
        NoPassive,
        NoSupportedIDP,
        PartialLogout,
        ProxyCountExceeded,
        RequestDenied,
        RequestUnsupported,
        RequestVersionDeprecated,
        RequestVersionTooHigh,
        RequestVersionTooLow,
        ResourceNotRecognized,
        TooManyResponses,
        UnknownAttrProfile,
        UnknownPrincipal,
        UnsupportedBinding,
    }
}
