#if NETFULL
using System;
using System.IdentityModel.Tokens;

namespace AuthXSSOServiceProvider.Saml.Tokens
{
    class SamlResponseIssuerNameRegistry : IssuerNameRegistry
    {
        public override string GetIssuerName(SecurityToken securityToken, string requestedIssuerName)
        {
            return requestedIssuerName;
        }

        public override string GetIssuerName(SecurityToken securityToken)
        {
            throw new InvalidOperationException();
        }
    }
}
#endif
