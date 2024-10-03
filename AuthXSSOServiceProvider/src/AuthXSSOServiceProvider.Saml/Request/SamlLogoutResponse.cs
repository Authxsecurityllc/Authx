using System;
using System.Xml;
using System.Xml.Linq;
#if NETFULL
using System.IdentityModel.Tokens;
#else
using Microsoft.IdentityModel.Tokens.Saml;
#endif

namespace AuthXSSOServiceProvider.Saml
{
    public class SamlLogoutResponse : SamlResponse
    {
        public override string ElementName => Schemas.SamlConstants.Message.LogoutResponse;

        public SamlLogoutResponse(SamlConfiguration config) : base(config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            Destination = config.SingleLogoutDestination;
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != ElementName)
            {
                throw new SamlRequestException("Not a Saml Logout Response.");
            }
        }

        public override XmlDocument ToXml()
        {
            var envelope = new XElement(Schemas.SamlConstants.ProtocolNamespaceX + ElementName);

            envelope.Add(base.GetXContent());
            XmlDocument = envelope.ToXmlDocument();
            return XmlDocument;
        }

        protected internal override void Read(string xml, bool validate = false, bool detectReplayedTokens = true)
        {
            base.Read(xml, validate, detectReplayedTokens);

            SessionIndex = XmlDocument.DocumentElement[Schemas.SamlConstants.Message.SessionIndex, Schemas.SamlConstants.ProtocolNamespace.OriginalString].GetValueOrNull<string>();
        }
    }
}
