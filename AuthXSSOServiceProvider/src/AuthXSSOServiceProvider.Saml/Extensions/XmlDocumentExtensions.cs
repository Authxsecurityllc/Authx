using AuthXSSOServiceProvider.Saml.Cryptography;
using AuthXSSOServiceProvider.Saml.Schemas;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml
{
    internal static class XmlDocumentExtensions
    {
        internal static XmlDocument SignDocument(this XmlDocument xmlDocument, X509Certificate2 certificate, string signatureAlgorithm, string xmlCanonicalizationMethod, X509IncludeOption includeOption, string id)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            var signedXml = new SamlSignedXml(xmlDocument.DocumentElement, certificate, signatureAlgorithm, xmlCanonicalizationMethod);
            signedXml.ComputeSignature(includeOption, id);

            var issuer = xmlDocument.DocumentElement[SamlConstants.Message.Issuer, SamlConstants.AssertionNamespace.OriginalString];
            xmlDocument.DocumentElement.InsertAfter(xmlDocument.ImportNode(signedXml.GetXml(), true), issuer);
            return xmlDocument;
        }
        internal static void SignAssertion(this XmlDocument xmlDocument, XmlElement xmlAssertionElement, X509Certificate2 certificate, string signatureAlgorithm, string xmlCanonicalizationMethod, X509IncludeOption includeOption)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            var id = xmlAssertionElement.GetAttribute(SamlConstants.Message.Id);

            var signedXml = new SamlSignedXml(xmlAssertionElement, certificate, signatureAlgorithm, xmlCanonicalizationMethod);
            signedXml.ComputeSignature(includeOption, id);

            var issuer = xmlAssertionElement[SamlConstants.Message.Issuer, SamlConstants.AssertionNamespace.OriginalString];
            xmlAssertionElement.InsertAfter(xmlDocument.ImportNode(signedXml.GetXml(), true), issuer);
        }
        internal static XDocument ToXDocument(this XmlDocument xmlDocument)
        {
            using (var reader = xmlDocument.CreateNavigator().ReadSubtree())
            {
                return XDocument.Load(reader);
            }
        }
        internal static XElement ToXElement(this XmlDocument xmlDocument)
        {
            using (var reader = xmlDocument.CreateNavigator().ReadSubtree())
            {
                return XElement.Load(reader);
            }
        }
    }
}