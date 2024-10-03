using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;
using AuthXSSOServiceProvider.Saml.Schemas;
using System;
using System.Security.Principal;

namespace AuthXSSOServiceProvider.Saml
{
    public class SamlAuthnRequest : SamlRequest
    {
        public override string ElementName => SamlConstants.Message.AuthnRequest;
        public bool? ForceAuthn { get; set; }
        public bool? IsPassive { get; set; }
        public Subject Subject { get; set; }
        public NameIdPolicy NameIdPolicy { get; set; }
        public int? AssertionConsumerServiceIndex { get; set; }
        public Uri AssertionConsumerServiceUrl { get; set; }
        public int? AttributeConsumingServiceIndex { get; set; }
        public Uri ProtocolBinding { get; set; }
        public string ProviderName { get; set; }
        public RequestedAuthnContext RequestedAuthnContext { get; set; }
        public Condition Conditions { get; set; }
        public Scoping Scoping { get; set; }

        public SamlAuthnRequest(SamlConfiguration config) : base(config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            Destination = config.SingleSignOnDestination;
        }

        public override XmlDocument ToXml()
        {
            var envelope = new XElement(SamlConstants.ProtocolNamespaceX + ElementName);

            envelope.Add(base.GetXContent());
            envelope.Add(GetXContent());

            XmlDocument = envelope.ToXmlDocument();
            return XmlDocument;
        }

        protected override IEnumerable<XObject> GetXContent()
        {
            if (ForceAuthn.HasValue)
            {
                yield return new XAttribute(SamlConstants.Message.ForceAuthn, ForceAuthn);
            }

            if (IsPassive.HasValue)
            {
                yield return new XAttribute(SamlConstants.Message.IsPassive, IsPassive);
            }

            if (AssertionConsumerServiceIndex != null)
            {
                yield return new XAttribute(SamlConstants.Message.AssertionConsumerServiceIndex, AssertionConsumerServiceIndex);
            }

            if (AssertionConsumerServiceUrl != null)
            {
                yield return new XAttribute(SamlConstants.Message.AssertionConsumerServiceURL, AssertionConsumerServiceUrl);
            }

            if (AttributeConsumingServiceIndex != null)
            {
                yield return new XAttribute(SamlConstants.Message.AttributeConsumingServiceIndex, AttributeConsumingServiceIndex);
            }

            if (ProtocolBinding != null)
            {
                yield return new XAttribute(SamlConstants.Message.ProtocolBinding, ProtocolBinding);
            }

            if (!string.IsNullOrEmpty(ProviderName))
            {
                yield return new XAttribute(SamlConstants.Message.ProviderName, ProviderName);
            }

            if (Conditions != null)
            {
                yield return Conditions.ToXElement();
            }

            if (Subject != null)
            {
                yield return Subject.ToXElement();
            }

            if (NameIdPolicy != null)
            {
                yield return NameIdPolicy.ToXElement();
            }

            if (RequestedAuthnContext != null)
            {
                yield return RequestedAuthnContext.ToXElement();
            }

            if (Scoping != null)
            {
                yield return Scoping.ToXElement();
            }
        }

        protected internal override void Read(string xml, bool validate = false, bool detectReplayedTokens = true)
        {
            base.Read(xml, validate, detectReplayedTokens);

            ForceAuthn = XmlDocument.DocumentElement.Attributes[SamlConstants.Message.ForceAuthn].GetValueOrNull<bool>();

            IsPassive = XmlDocument.DocumentElement.Attributes[SamlConstants.Message.IsPassive].GetValueOrNull<bool>();

            AssertionConsumerServiceIndex = XmlDocument.DocumentElement.Attributes[SamlConstants.Message.AssertionConsumerServiceIndex].GetValueOrNull<int?>();

            AssertionConsumerServiceUrl = XmlDocument.DocumentElement.Attributes[SamlConstants.Message.AssertionConsumerServiceURL].GetValueOrNull<Uri>();

            AttributeConsumingServiceIndex = XmlDocument.DocumentElement.Attributes[SamlConstants.Message.AttributeConsumingServiceIndex].GetValueOrNull<int?>();

            ProtocolBinding = XmlDocument.DocumentElement.Attributes[SamlConstants.Message.ProtocolBinding].GetValueOrNull<Uri>();

            ProviderName = XmlDocument.DocumentElement.Attributes[SamlConstants.Message.ProviderName].GetValueOrNull<string>();

            Subject = XmlDocument.DocumentElement[SamlConstants.Message.Subject, SamlConstants.AssertionNamespace.OriginalString].GetElementOrNull<Subject>();

            NameIdPolicy = XmlDocument.DocumentElement[SamlConstants.Message.NameIdPolicy, SamlConstants.ProtocolNamespace.OriginalString].GetElementOrNull<NameIdPolicy>();

            RequestedAuthnContext = XmlDocument.DocumentElement[SamlConstants.Message.RequestedAuthnContext, SamlConstants.ProtocolNamespace.OriginalString].GetElementOrNull<RequestedAuthnContext>();

            Scoping = XmlDocument.DocumentElement[SamlConstants.Message.Scoping, SamlConstants.ProtocolNamespace.OriginalString].GetElementOrNull<Scoping>();
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != ElementName)
            {
                throw new SamlRequestException("Not a Saml Authn Request.");
            }
        }
    }
}
