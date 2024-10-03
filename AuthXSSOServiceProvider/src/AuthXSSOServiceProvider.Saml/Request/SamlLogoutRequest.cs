using AuthXSSOServiceProvider.Saml.Claims;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Xml;
using System.Xml.Linq;
#if NETFULL
using System.IdentityModel.Tokens;
#else
using Microsoft.IdentityModel.Tokens.Saml2;
#endif

namespace AuthXSSOServiceProvider.Saml
{
    public class SamlLogoutRequest : SamlRequest
    {
        public override string ElementName => Schemas.SamlConstants.Message.LogoutRequest;

        public DateTimeOffset? NotOnOrAfter { get; set; }
        public Uri Reason { get; set; }

        public SamlLogoutRequest(SamlConfiguration config) : base(config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            Destination = config.SingleLogoutDestination;
            NotOnOrAfter = DateTimeOffset.UtcNow.AddMinutes(10);
        }

        public SamlLogoutRequest(SamlConfiguration config, ClaimsPrincipal currentPrincipal) : this(config)
        {
            var identity = currentPrincipal.Identities.First();
            if (identity.IsAuthenticated)
            {
                var nameIdFormat = ReadClaimValue(identity, SamlClaimTypes.NameIdFormat, false);
                if (string.IsNullOrEmpty(nameIdFormat)) 
                {
                    NameId = new Saml2NameIdentifier(ReadClaimValue(identity, ClaimTypes.NameIdentifier));
                }
                else
                {
                    NameId = new Saml2NameIdentifier(ReadClaimValue(identity, ClaimTypes.NameIdentifier), new Uri(nameIdFormat));

                }
              
            }
        }

        private static string ReadClaimValue(ClaimsIdentity identity, string claimType, bool required = true)
        {
            var claim = identity.Claims.FirstOrDefault(c => c.Type == claimType);
            if (claim == null)
            {
                if (required)
                {
                    throw new InvalidOperationException($"Claim Type '{claimType}' is required to do logout.");
                }
                else
                {
                    return null;
                }
            }
            return claim.Value;
        }

        public override XmlDocument ToXml()
        {
            var envelope = new XElement(Schemas.SamlConstants.ProtocolNamespaceX + ElementName);

            envelope.Add(base.GetXContent());
            envelope.Add(GetXContent());

            XmlDocument = envelope.ToXmlDocument();
            return XmlDocument;
        }

        protected override IEnumerable<XObject> GetXContent()
        {
            if (NotOnOrAfter.HasValue)
            {
                yield return new XAttribute(Schemas.SamlConstants.Message.NotOnOrAfter, NotOnOrAfter.Value.UtcDateTime.ToString(Schemas.SamlConstants.DateTimeFormat, CultureInfo.InvariantCulture));
            }

            if (Reason != null)
            {
                yield return new XAttribute(Schemas.SamlConstants.Message.Reason, Reason.OriginalString);
            }

            if (NameId != null)
            {
                var nameIdContent = new List<object>() { NameId.Value };
                if (NameId.Format != null)
                {
                    nameIdContent.Add(new XAttribute(Schemas.SamlConstants.Message.Format, NameId.Format));
                }
                if (NameId.NameQualifier != null)
                {
                    nameIdContent.Add(new XAttribute(Schemas.SamlConstants.Message.NameQualifier, NameId.NameQualifier));
                }
                if (NameId.SPNameQualifier != null)
                {
                    nameIdContent.Add(new XAttribute(Schemas.SamlConstants.Message.SpNameQualifier, NameId.SPNameQualifier));
                }
                yield return new XElement(Schemas.SamlConstants.AssertionNamespaceX + Schemas.SamlConstants.Message.NameId, nameIdContent);
            }

            if (SessionIndex != null)
            {
                yield return new XElement(Schemas.SamlConstants.ProtocolNamespaceX + Schemas.SamlConstants.Message.SessionIndex, SessionIndex);
            }
        }

        protected internal override void Read(string xml, bool validate = false, bool detectReplayedTokens = true)
        {
            base.Read(xml, validate, detectReplayedTokens);

            NameId = XmlDocument.DocumentElement[Schemas.SamlConstants.Message.NameId, Schemas.SamlConstants.AssertionNamespace.OriginalString].GetValueOrNull<Saml2NameIdentifier>();
            NameId.NameQualifier = XmlDocument.DocumentElement[Schemas.SamlConstants.Message.NameId, Schemas.SamlConstants.AssertionNamespace.OriginalString].GetAttribute(Schemas.SamlConstants.Message.NameQualifier);
            NameId.SPNameQualifier = XmlDocument.DocumentElement[Schemas.SamlConstants.Message.NameId, Schemas.SamlConstants.AssertionNamespace.OriginalString].GetAttribute(Schemas.SamlConstants.Message.SpNameQualifier);

            SessionIndex = XmlDocument.DocumentElement[Schemas.SamlConstants.Message.SessionIndex, Schemas.SamlConstants.ProtocolNamespace.OriginalString].GetValueOrNull<string>();
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != ElementName)
            {
                throw new SamlRequestException("Invalid Saml Logout Request.");
            }
        }
    }
}
