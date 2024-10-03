using AuthXSSOServiceProvider.Saml.Claims;
using AuthXSSOServiceProvider.Saml.Configuration;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Xml;
#if NETFULL
using System;
using System.IO;
using System.IdentityModel.Configuration;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
#else
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
#endif

namespace AuthXSSOServiceProvider.Saml.Tokens
{
    public class SamlResponseSecurityTokenHandler : Saml2SecurityTokenHandler
    {
#if !NETFULL
        public TokenValidationParameters TokenValidationParameters { get; protected set; }
#endif

        public static SamlResponseSecurityTokenHandler GetSamlSecurityTokenHandler(SamlIdentityConfiguration configuration)
        {
            var handler = new SamlResponseSecurityTokenHandler();
#if NETFULL
            handler.Configuration = new SecurityTokenHandlerConfiguration
            {
                SaveBootstrapContext = configuration.SaveBootstrapContext,
                AudienceRestriction = configuration.AudienceRestriction,
                IssuerNameRegistry = configuration.IssuerNameRegistry,
                CertificateValidationMode = configuration.CertificateValidationMode,
                RevocationMode = configuration.RevocationMode,
                CertificateValidator = configuration.CertificateValidator,
                DetectReplayedTokens = configuration.DetectReplayedTokens,
                Caches = configuration.Caches,
                TokenReplayCacheExpirationPeriod = configuration.TokenReplayCacheExpirationPeriod,
                IssuerTokenResolver = configuration.IssuerTokenResolver
            };

            handler.SamlSecurityTokenRequirement.NameClaimType = ClaimTypes.NameIdentifier;
#else
            handler.TokenValidationParameters = configuration;
            handler.Serializer = new SamlTokenSerializer(configuration.DecryptionCertificates);
#endif
            return handler;
        }

#if NETFULL
        public ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token, SamlResponse SamlResponse, bool detectReplayedTokens)
#else
        public ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token, string tokenString, SamlResponse SamlResponse, bool detectReplayedTokens)
#endif
        {
            var SamlSecurityToken = token as Saml2SecurityToken;
            
#if NETFULL
            ValidateConditions(SamlSecurityToken.Assertion.Conditions, SamlSecurityTokenRequirement.ShouldEnforceAudienceRestriction(Configuration.AudienceRestriction.AudienceMode, SamlSecurityToken));
#else
            ValidateConditions(SamlSecurityToken, TokenValidationParameters);
#endif

            if (detectReplayedTokens)
            {
#if NETFULL
                if (Configuration.DetectReplayedTokens)
                {
                    DetectReplayedToken(SamlSecurityToken);
                }
#else
                if (TokenValidationParameters.ValidateTokenReplay)
                {
                    ValidateTokenReplay(SamlSecurityToken.Assertion.Conditions.NotOnOrAfter, tokenString, TokenValidationParameters);
                }
#endif
            }

#if NETFULL
            var identity = CreateClaims(SamlSecurityToken);
#else
            var identity = CreateClaimsIdentity(SamlSecurityToken, TokenValidationParameters.ValidIssuer, TokenValidationParameters);
#endif
            if (SamlSecurityToken.Assertion.Subject.NameId != null)
            {
                SamlResponse.NameId = SamlSecurityToken.Assertion.Subject.NameId;
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, SamlResponse.NameId.Value));

                if (SamlResponse.NameId.Format != null)
                {
                    identity.AddClaim(new Claim(SamlClaimTypes.NameIdFormat, SamlResponse.NameId.Format.OriginalString));
                }
            }
#if NETFULL
            if (Configuration.SaveBootstrapContext)
            {
                identity.BootstrapContext = new BootstrapContext(SamlSecurityToken, this);
            }
#else
            if (TokenValidationParameters.SaveSigninToken)
            {
                identity.BootstrapContext = tokenString;
            }
#endif

            return new List<ClaimsIdentity>(1) { identity }.AsReadOnly();
        }

        public override string WriteToken(SecurityToken token)
        {
            var builder = new StringBuilder();
            using (var writer = XmlWriter.Create(builder))
            {
                WriteToken(writer, token);
            }
            return builder.ToString();
        }

        protected override void ProcessAuthenticationStatement(Saml2AuthenticationStatement statement, ClaimsIdentity identity, string issuer)
        {
            if (statement?.AuthenticationContext?.DeclarationReference != null)
            {
                // Add AuthnContextDeclRef claim
                identity.AddClaim(new Claim($"{ClaimTypes.AuthenticationMethod}/declarationreference", statement.AuthenticationContext.DeclarationReference.OriginalString, ClaimValueTypes.String, issuer));
                // Remove AuthnContextDeclRef
                statement.AuthenticationContext.DeclarationReference = null;
            }
            base.ProcessAuthenticationStatement(statement, identity, issuer);
        }
    }
}
