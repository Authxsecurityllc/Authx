using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;
using AuthXSSOServiceProvider.Saml.Util;
#if NETFULL
using System.IdentityModel.Tokens;
#else
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
#endif

namespace AuthXSSOServiceProvider.Saml
{
    public abstract class SamlResponse : SamlRequest
    {
        public Schemas.SamlStatusCodes Status { get; set; }

        public string StatusMessage { get; set; }
        public Saml2Id InResponseTo { get; set; }
        public string InResponseToAsString
        {
            get { return InResponseTo.Value; }
            set { InResponseTo = new Saml2Id(value); }
        }

        public SamlResponse(SamlConfiguration config) : base(config)
        { }

        protected override IEnumerable<XObject> GetXContent()
        {
            foreach (var item in  base.GetXContent())
            {
                yield return item;
            }

            var statusEnvelope = new XElement(Schemas.SamlConstants.ProtocolNamespaceX + Schemas.SamlConstants.Message.Status,
                new XElement(Schemas.SamlConstants.ProtocolNamespaceX + Schemas.SamlConstants.Message.StatusCode,
                    new XAttribute(Schemas.SamlConstants.Message.Value, SamlStatusCodeUtil.ToString(Status))));

            if (!string.IsNullOrWhiteSpace(StatusMessage))
            {
                statusEnvelope.Add(new XElement(Schemas.SamlConstants.ProtocolNamespaceX + Schemas.SamlConstants.Message.StatusMessage, StatusMessage));
            }

            yield return statusEnvelope;

            if (InResponseTo != null)
            {
                yield return new XAttribute(Schemas.SamlConstants.Message.InResponseTo, InResponseToAsString);
            }
        }

        protected internal override void Read(string xml, bool validate = false, bool detectReplayedTokens = true)
        {
            base.Read(xml, validate, detectReplayedTokens);

            InResponseTo = XmlDocument.DocumentElement.Attributes[Schemas.SamlConstants.Message.InResponseTo].GetValueOrNull<Saml2Id>();

            ValidateStatus();
        }

        protected virtual void ValidateStatus()
        {
            Status = SamlStatusCodeUtil.ToEnum(XmlDocument.DocumentElement[Schemas.SamlConstants.Message.Status, Schemas.SamlConstants.ProtocolNamespace.OriginalString][Schemas.SamlConstants.Message.StatusCode, Schemas.SamlConstants.ProtocolNamespace.OriginalString].Attributes[Schemas.SamlConstants.Message.Value].GetValueOrNull<string>());

            StatusMessage = XmlDocument.DocumentElement[Schemas.SamlConstants.Message.Status, Schemas.SamlConstants.ProtocolNamespace.OriginalString][Schemas.SamlConstants.Message.StatusMessage, Schemas.SamlConstants.ProtocolNamespace.OriginalString].GetValueOrNull<string>();
        }
    }
}
