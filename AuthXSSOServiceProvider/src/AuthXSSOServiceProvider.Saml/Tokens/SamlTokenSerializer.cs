#if !NETFULL
using AuthXSSOServiceProvider.Saml.Cryptography;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace AuthXSSOServiceProvider.Saml.Tokens
{
    internal class SamlTokenSerializer : Saml2Serializer
    {
        private readonly IEnumerable<X509Certificate2> decryptionCertificates;

        public SamlTokenSerializer(IEnumerable<X509Certificate2> decryptionCertificates) : base() 
        {
            this.decryptionCertificates = decryptionCertificates;
        }

        protected override Saml2NameIdentifier ReadEncryptedId(XmlDictionaryReader reader)
        {
            if (decryptionCertificates?.Count() > 0)
            {
                var xmlDocument = reader.ReadOuterXml().ToXmlDocument();

                var exceptions = new List<Exception>();
                foreach (var decryptionCertificate in decryptionCertificates)
                {
                    try
                    {
                        new SamlEncryptedXml(xmlDocument, decryptionCertificate.GetSamlRSAPrivateKey()).DecryptDocument();
                        var decryptedReader = XmlDictionaryReader.CreateDictionaryReader(new XmlNodeReader(xmlDocument.DocumentElement.FirstChild));
                        return ReadNameIdentifier(decryptedReader, null);
                    }
                    catch (Exception e)
                    {
                        exceptions.Add(e);
                    }
                }
                throw new AggregateException("Failed to decrypt message", exceptions);
            }
            else
            {
                return base.ReadEncryptedId(reader);
            }
        }

        protected override Saml2AuthenticationContext ReadAuthenticationContext(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.AuthnContext, Saml2Constants.Namespace);
            try
            {
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.AuthnContextType, Saml2Constants.Namespace);

                if (reader.IsEmptyElement)
                    throw new Saml2SecurityTokenReadException("IDX13312: 'AuthnContext' cannot be empty.");

                reader.ReadStartElement();
                Uri classRef = null;
                Uri declRef = null;
                if (reader.IsStartElement(Saml2Constants.Elements.AuthnContextClassRef, Saml2Constants.Namespace))
                    classRef = ReadSimpleUriElement(reader, Saml2Constants.Elements.AuthnContextClassRef, UriKind.RelativeOrAbsolute, false);
                if (reader.IsStartElement(Saml2Constants.Elements.AuthnContextDecl, Saml2Constants.Namespace))
                    throw new Saml2SecurityTokenReadException("IDX13118: A <saml:AuthnContextDecl> element was encountered.To handle by-value authentication context declarations, extend SamlSecurityTokenHandler and override ReadAuthenticationContext.In addition, it may be necessary to extend SamlAuthenticationContext so that its data model can accommodate the declaration value.");
                if (reader.IsStartElement(Saml2Constants.Elements.AuthnContextDeclRef, Saml2Constants.Namespace))
                    declRef = ReadSimpleUriElement(reader, Saml2Constants.Elements.AuthnContextDeclRef, UriKind.RelativeOrAbsolute, false);
                else if (classRef == null)
                    reader.ReadStartElement(Saml2Constants.Elements.AuthnContextDeclRef, Saml2Constants.Namespace);
                var authnContext = new Saml2AuthenticationContext();

                if (classRef != null)
                    authnContext.ClassReference = classRef;

                if (declRef != null)
                    authnContext.DeclarationReference = declRef;
                while (reader.IsStartElement(Saml2Constants.Elements.AuthenticatingAuthority, Saml2Constants.Namespace))
                    authnContext.AuthenticatingAuthorities.Add(ReadSimpleUriElement(reader, Saml2Constants.Elements.AuthenticatingAuthority, UriKind.RelativeOrAbsolute, false));

                reader.ReadEndElement();
                return authnContext;
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw new Saml2SecurityTokenReadException("IDX13102: Exception thrown while reading 'AuthnContext' for SamlSecurityToken.", ex);
            }
        }
        internal static Uri ReadSimpleUriElement(XmlDictionaryReader reader, string element, UriKind kind, bool requireUri)
        {
            try
            {
                if (reader.IsEmptyElement)
                    throw new Saml2SecurityTokenReadException("IDX13104: Unable to read SamlSecurityToken. Expecting XmlReader to be at element: 'Uri', found 'Empty Element'");

                XmlUtil.ValidateXsiType(reader, XmlSignatureConstants.Attributes.AnyUri, XmlSignatureConstants.XmlSchemaNamespace);
                reader.MoveToElement();
                string value = reader.ReadElementContentAsString();

                if (string.IsNullOrEmpty(value))
                    throw new Saml2SecurityTokenReadException($"IDX13136: Unable to read for SamlSecurityToken. Required Element: '{element}' is missing or empty.");

                if (requireUri && !Uri.TryCreate(value, kind, out Uri tempUri))
                    throw new Saml2SecurityTokenReadException($"IDX13107: When reading '{element}', '{element}' was not a Absolute Uri, was: '{value}'.");

                return new Uri(value, kind);
            }
            catch (Exception ex)
            {
                throw new Saml2SecurityTokenReadException($"IDX13102: Exception thrown while reading '{element}' for SamlSecurityToken.", ex);
            }
        }
    }
}
#endif
