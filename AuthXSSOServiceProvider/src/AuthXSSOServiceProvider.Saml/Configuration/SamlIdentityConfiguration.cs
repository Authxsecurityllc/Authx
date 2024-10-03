using System.ServiceModel.Security;
using System.Collections.Generic;
#if NETFULL
using AuthXSSOServiceProvider.Saml.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Configuration;
using System.IdentityModel.Tokens;
#else
using System.Linq;
using AuthXSSOServiceProvider.Saml.Util;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.IdentityModel.Selectors;
#endif

namespace AuthXSSOServiceProvider.Saml.Configuration
{
    public class SamlIdentityConfiguration :
#if NETFULL
        IdentityConfiguration
#else
        TokenValidationParameters
#endif
    {

#if !NETFULL
        public X509CertificateValidator CertificateValidator { get; set; }

        public IEnumerable<X509Certificate2> DecryptionCertificates { get; set; }
#endif

        public static SamlIdentityConfiguration GetIdentityConfiguration(SamlConfiguration config)
        {
            var configuration = new SamlIdentityConfiguration();

#if NETFULL
            configuration.SaveBootstrapContext = config.SaveBootstrapContext;
            configuration.AudienceRestriction = GetAudienceRestriction(config.AudienceRestricted, config.AllowedAudienceUris);
            configuration.IssuerNameRegistry = new SamlResponseIssuerNameRegistry();
            configuration.CertificateValidationMode = config.CertificateValidationMode;
            configuration.RevocationMode = config.RevocationMode;
            SetCustomCertificateValidator(configuration, config);
            if (config.CustomIssuerTokenResolver != null)
            {
                configuration.IssuerTokenResolver = config.CustomIssuerTokenResolver;
            }

            configuration.DetectReplayedTokens = config.DetectReplayedTokens;
            if (config.TokenReplayCache != null)
            {
                configuration.Caches = config.TokenReplayCache;
            }
            if (config.TokenReplayCacheExpirationPeriod.HasValue)
            {
                configuration.TokenReplayCacheExpirationPeriod = config.TokenReplayCacheExpirationPeriod.Value;
            }
            configuration.Initialize();
#else
            configuration.SaveSigninToken = config.SaveBootstrapContext;
            configuration.ValidateAudience = config.AudienceRestricted;
            configuration.ValidAudiences = config.AllowedAudienceUris.Select(a => a);
            configuration.ValidIssuer = config.AllowedIssuer;

            configuration.ValidateTokenReplay = config.DetectReplayedTokens;
            if (config.TokenReplayCache != null)
            {
                configuration.TokenReplayCache = config.TokenReplayCache;
            }

            configuration.NameClaimType = ClaimTypes.NameIdentifier;

            configuration.CertificateValidator = new SamlCertificateValidator
            {
                CertificateValidationMode = config.CertificateValidationMode,
                RevocationMode = config.RevocationMode,
            };
            configuration.DecryptionCertificates = config.DecryptionCertificates;
            SetCustomCertificateValidator(configuration, config);
#endif

            return configuration;
        }

        private static void SetCustomCertificateValidator(SamlIdentityConfiguration configuration, SamlConfiguration config)
        {
            if (config.CertificateValidationMode == X509CertificateValidationMode.Custom)
            {
                if (config.CustomCertificateValidator is null)
                {
                    throw new SamlConfigurationException("A CustomCertificateValidator is required when setting CertificateValidationMode = X509CertificateValidationMode.Custom");
                }

                configuration.CertificateValidator = config.CustomCertificateValidator;
            }
        }

#if NETFULL
        private static AudienceRestriction GetAudienceRestriction(bool audienceRestricted, IEnumerable<string> allowedAudienceUris)
        {
            var audienceRestriction = new AudienceRestriction(audienceRestricted ? System.IdentityModel.Selectors.AudienceUriMode.Always : System.IdentityModel.Selectors.AudienceUriMode.Never);
            if (audienceRestricted)
            {
                foreach (var audienceUri in allowedAudienceUris)
                {
                    audienceRestriction.AllowedAudienceUris.Add(new Uri(audienceUri));
                }
            }
            return audienceRestriction;
        }
#endif
    }
}
