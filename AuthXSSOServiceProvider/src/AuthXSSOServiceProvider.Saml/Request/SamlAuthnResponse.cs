using AuthXSSOServiceProvider.Saml.Tokens;
using System;
using System.Linq;
using System.Security.Claims;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using AuthXSSOServiceProvider.Saml.Cryptography;
using System.Diagnostics;
using System.Collections.Generic;
using System.Xml.Linq;
#if NETFULL
using System.IdentityModel.Tokens;
using System.IdentityModel.Protocols.WSTrust;
#else
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
#endif


namespace AuthXSSOServiceProvider.Saml
{
    public class SamlAuthnResponse : SamlResponse
    {
        public override string ElementName => Schemas.SamlConstants.Message.AuthnResponse;

        internal IEnumerable<X509Certificate2> DecryptionCertificates { get; private set; }
        internal X509Certificate2 EncryptionCertificate { get; private set; }
        public ClaimsIdentity ClaimsIdentity { get; set; }
        public Saml2SecurityToken SamlSecurityToken { get; protected set; }
        public DateTimeOffset SecurityTokenValidFrom { get { return SamlSecurityToken.ValidFrom.ToDateTimeOffsetOutOfRangeProtected(); } }
        public DateTimeOffset SecurityTokenValidTo { get { return SamlSecurityToken.ValidTo.ToDateTimeOffsetOutOfRangeProtected(); } }
        public SamlResponseSecurityTokenHandler Saml2SecurityTokenHandler { get; protected set; }

        public SamlAuthnResponse(SamlConfiguration config) : base(config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            Destination = config.SingleSignOnDestination;

            if (config.DecryptionCertificates?.Count() > 0)
            {
                DecryptionCertificates = config.DecryptionCertificates.Where(c => c.GetSamlRSAPrivateKey() != null);
                if (!(DecryptionCertificates?.Count() > 0))
                {
                    throw new ArgumentException("No RSA Private Key present in Decryption Certificates or missing private key read credentials.");
                }
            }
            if (config.EncryptionCertificate != null)
            {
                EncryptionCertificate = config.EncryptionCertificate;
                if (config.EncryptionCertificate.GetRSAPublicKey() == null)
                {
                    throw new ArgumentException("No RSA Public Key present in Encryption Certificate.");
                }
            }
            Saml2SecurityTokenHandler = SamlResponseSecurityTokenHandler.GetSamlSecurityTokenHandler(IdentityConfiguration);
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != ElementName)
            {
                throw new SamlRequestException("Not a Saml Authn Response.");
            }
        }
        public Saml2SecurityToken CreateSecurityToken(string appliesToAddress, Uri authnContext = null, Uri declAuthnContext = null, int subjectConfirmationLifetime = 5, int issuedTokenLifetime = 60)
        {
            if (appliesToAddress == null) throw new ArgumentNullException(nameof(appliesToAddress));
            if (ClaimsIdentity == null) throw new ArgumentNullException("ClaimsIdentity property");

            var tokenDescriptor = CreateTokenDescriptor(ClaimsIdentity.Claims, appliesToAddress, issuedTokenLifetime);
            SamlSecurityToken = Saml2SecurityTokenHandler.CreateToken(tokenDescriptor) as Saml2SecurityToken;

            AddNameIdFormat(ClaimsIdentity.Claims);
            AddAuthenticationStatement(CreateAuthenticationStatement(authnContext, declAuthnContext));
            AddSubjectConfirmation(CreateSubjectConfirmation(subjectConfirmationLifetime));

            return SamlSecurityToken;
        }
        public Saml2SecurityToken CreateSecurityToken(SecurityTokenDescriptor tokenDescriptor, Saml2AuthenticationStatement authenticationStatement, Saml2SubjectConfirmation subjectConfirmation)
        {
            if (tokenDescriptor == null) throw new ArgumentNullException(nameof(tokenDescriptor));
            if (authenticationStatement == null) throw new ArgumentNullException(nameof(authenticationStatement));
            if (subjectConfirmation == null) throw new ArgumentNullException(nameof(subjectConfirmation));

            SamlSecurityToken = Saml2SecurityTokenHandler.CreateToken(tokenDescriptor) as Saml2SecurityToken;

            AddNameIdFormat();
            AddAuthenticationStatement(authenticationStatement);
            AddSubjectConfirmation(subjectConfirmation);

            return SamlSecurityToken;
        }

        protected virtual SecurityTokenDescriptor CreateTokenDescriptor(IEnumerable<Claim> claims, string appliesToAddress, int issuedTokenLifetime)
        {
            if (string.IsNullOrEmpty(Issuer)) throw new ArgumentNullException("Issuer property");

            var now = DateTimeOffset.UtcNow;
            var tokenDescriptor = new SecurityTokenDescriptor();
            tokenDescriptor.Subject = new ClaimsIdentity(claims.Where(c => c.Type != ClaimTypes.NameIdentifier));
#if NETFULL
            tokenDescriptor.TokenType = Schemas.SamlTokenTypes.SamlTokenProfile11.OriginalString;
            tokenDescriptor.Lifetime = new Lifetime(now.UtcDateTime, now.AddMinutes(issuedTokenLifetime).UtcDateTime);
            tokenDescriptor.AppliesToAddress = appliesToAddress;
            tokenDescriptor.TokenIssuerName = Issuer;
#else
            tokenDescriptor.Expires = now.AddMinutes(issuedTokenLifetime).UtcDateTime;
            tokenDescriptor.Audience = appliesToAddress;
            tokenDescriptor.Issuer = Issuer;
#endif
            return tokenDescriptor;
        }

        protected virtual Saml2SubjectConfirmation CreateSubjectConfirmation(int subjectConfirmationLifetime)
        {
            if (Destination == null) throw new ArgumentNullException("Destination property");

            var subjectConfirmationData = new Saml2SubjectConfirmationData
            {
                Recipient = Destination,
                NotOnOrAfter = DateTimeOffset.UtcNow.AddMinutes(subjectConfirmationLifetime).UtcDateTime,
            };

            if (InResponseTo != null)
            {
                subjectConfirmationData.InResponseTo = InResponseTo;
            }

            return new Saml2SubjectConfirmation(Schemas.SamlConstants.SamlBearerToken, subjectConfirmationData);
        }

        protected virtual Saml2AuthenticationStatement CreateAuthenticationStatement(Uri authnContext, Uri declAuthnContext)
        {
            var SamlAuthenticationContext = new Saml2AuthenticationContext();
            if (authnContext == null && declAuthnContext == null)
            {
                SamlAuthenticationContext.ClassReference = Schemas.AuthnContextClassTypes.PasswordProtectedTransport;
            }
            else
            {
                if (authnContext != null)
                {
                    SamlAuthenticationContext.ClassReference = authnContext;
                }
                if (declAuthnContext != null)
                {
                    SamlAuthenticationContext.DeclarationReference = declAuthnContext;
                }
            }
            var authenticationStatement = new Saml2AuthenticationStatement(SamlAuthenticationContext);
            authenticationStatement.SessionIndex = SessionIndex;
            return authenticationStatement;
        }

        private void AddNameIdFormat(IEnumerable<Claim> claims = null)
        {
            if (NameId != null)
            {
                SamlSecurityToken.Assertion.Subject.NameId = NameId;
            }
            else if (claims != null)
            {
                var nameIdValue = claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).FirstOrDefault();
                if (!string.IsNullOrEmpty(nameIdValue))
                {
                    SamlSecurityToken.Assertion.Subject.NameId = new Saml2NameIdentifier(nameIdValue);
                }
            }
        }

        private void AddSubjectConfirmation(Saml2SubjectConfirmation subjectConfirmation)
        {
            SamlSecurityToken.Assertion.Subject.SubjectConfirmations.Clear();
            SamlSecurityToken.Assertion.Subject.SubjectConfirmations.Add(subjectConfirmation);
        }

        private void AddAuthenticationStatement(Saml2AuthenticationStatement authenticationStatement)
        {
            SamlSecurityToken.Assertion.Statements.Add(authenticationStatement);
        }

        public override XmlDocument ToXml()
        {
            var envelope = new XElement(Schemas.SamlConstants.ProtocolNamespaceX + ElementName);
            envelope.Add(base.GetXContent());
            XmlDocument = envelope.ToXmlDocument();

            if (SamlSecurityToken != null)
            {
                var tokenXml = Saml2SecurityTokenHandler.WriteToken(SamlSecurityToken);

                var status = XmlDocument.DocumentElement[Schemas.SamlConstants.Message.Status, Schemas.SamlConstants.ProtocolNamespace.OriginalString];
                XmlDocument.DocumentElement.InsertAfter(XmlDocument.ImportNode(tokenXml.ToXmlDocument().DocumentElement, true), status);
            }

            return XmlDocument;
        }

        protected internal void SignAuthnResponseAssertion(X509IncludeOption certificateIncludeOption)
        {
            if (Status != Schemas.SamlStatusCodes.Success)
            {
                return;
            }

            Cryptography.SignatureAlgorithm.ValidateAlgorithm(Config.SignatureAlgorithm);
            Cryptography.XmlCanonicalizationMethod.ValidateCanonicalizationMethod(Config.XmlCanonicalizationMethod);
            XmlDocument.SignAssertion(GetAssertionElementReference(), Config.SigningCertificate, Config.SignatureAlgorithm, Config.XmlCanonicalizationMethod, certificateIncludeOption);
        }

        protected internal override void Read(string xml, bool validate = false, bool detectReplayedTokens = true)
        {
            base.Read(xml, validate, detectReplayedTokens);

            if (Status == Schemas.SamlStatusCodes.Success)
            {
                var assertionElement = GetAssertionElement();
                ValidateAssertionSubject(assertionElement);

#if NETFULL
                SamlSecurityToken = ReadSecurityToken(assertionElement);
                ClaimsIdentity = ReadClaimsIdentity(detectReplayedTokens);
#else
                var tokenString = assertionElement.OuterXml;
                SamlSecurityToken = ReadSecurityToken(tokenString);
                ClaimsIdentity = ReadClaimsIdentity(tokenString, detectReplayedTokens);
#endif
            }
        }

        XmlElement assertionElementCache = null;
        protected override XmlElement GetAssertionElement()
        {
            if (assertionElementCache == null)
            {
#if NETFULL || NETSTANDARD || NETCORE || NET50 || NET60
                assertionElementCache = GetAssertionElementReference().ToXmlDocument().DocumentElement;
#else
                assertionElementCache = GetAssertionElementReference();
#endif
            }
            return assertionElementCache;
        }

        protected XmlElement GetAssertionElementReference()
        {
            var assertionElements = XmlDocument.DocumentElement.SelectNodes($"//*[local-name()='{Schemas.SamlConstants.Message.Assertion}']/ancestor-or-self::*[local-name()='{Schemas.SamlConstants.Message.Assertion}'][last()]");
            if (assertionElements.Count != 1)
            {
                throw new SamlRequestException("There is not exactly one Assertion element. Maybe the response is encrypted (set the SamlConfiguration.DecryptionCertificate).");
            }
            return assertionElements[0] as XmlElement;
        }

        private void ValidateAssertionSubject(XmlNode assertionElement)
        {
            var subjectElement = assertionElement[Schemas.SamlConstants.Message.Subject, Schemas.SamlConstants.AssertionNamespace.OriginalString];
            if (subjectElement == null)
            {
                throw new SamlRequestException("Subject Not Found.");
            }

            ValidateSubjectConfirmationExpiration(subjectElement);
        }

        protected virtual void ValidateSubjectConfirmationExpiration(XmlElement subjectElement)
        {
            var subjectConfirmationElement = subjectElement[Schemas.SamlConstants.Message.SubjectConfirmation, Schemas.SamlConstants.AssertionNamespace.OriginalString];
            if (subjectConfirmationElement == null)
            {
                throw new SamlRequestException("SubjectConfirmationElement Not Found.");
            }

            var subjectConfirmationData = subjectConfirmationElement[Schemas.SamlConstants.Message.SubjectConfirmationData, Schemas.SamlConstants.AssertionNamespace.OriginalString];
            if (subjectConfirmationData == null)
            {
                throw new SamlRequestException("SubjectConfirmationData Not Found.");
            }

            var notOnOrAfter = subjectConfirmationData.Attributes[Schemas.SamlConstants.Message.NotOnOrAfter].GetValueOrNull<DateTimeOffset>();
            if (notOnOrAfter < DateTimeOffset.UtcNow)
            {
                throw new SamlRequestException($"Assertion has expired. Assertion valid NotOnOrAfter {notOnOrAfter}.");
            }
        }

#if NETFULL
        private Saml2SecurityToken ReadSecurityToken(XmlNode assertionElement)
        {
            using (var reader = new XmlNodeReader(assertionElement))
            {
                return Saml2SecurityTokenHandler.ReadToken(reader) as Saml2SecurityToken;
            }
        }

        private ClaimsIdentity ReadClaimsIdentity(bool detectReplayedTokens)
        {
            return Saml2SecurityTokenHandler.ValidateToken(SamlSecurityToken, this, detectReplayedTokens).First();
        }
#else
        private Saml2SecurityToken ReadSecurityToken(string tokenString)
        {
            return Saml2SecurityTokenHandler.ReadSaml2Token(tokenString);
        }

        private ClaimsIdentity ReadClaimsIdentity(string tokenString, bool detectReplayedTokens)
        {
            return Saml2SecurityTokenHandler.ValidateToken(SamlSecurityToken, tokenString, this, detectReplayedTokens).First();
        }
#endif

        protected override void DecryptMessage()
        {
            if (DecryptionCertificates?.Count() > 0)
            {
                var exceptions = new List<Exception>();
                foreach (var decryptionCertificate in DecryptionCertificates)
                {
                    try
                    {
                        new SamlEncryptedXml(XmlDocument, decryptionCertificate.GetSamlRSAPrivateKey()).DecryptDocument();
                        return;
                    }
                    catch (Exception e)
                    {
                        exceptions.Add(e);
                    }
                }
                throw new AggregateException("Failed to decrypt message", exceptions);
            }
        }

        protected internal void EncryptMessage()
        {
            if (Status != Schemas.SamlStatusCodes.Success)
            {
                return;
            }

            var envelope = new XElement(Schemas.SamlConstants.AssertionNamespaceX + Schemas.SamlConstants.Message.EncryptedAssertion);
            var status = XmlDocument.DocumentElement[Schemas.SamlConstants.Message.Status, Schemas.SamlConstants.ProtocolNamespace.OriginalString];
            XmlDocument.DocumentElement.InsertAfter(XmlDocument.ImportNode(envelope.ToXmlDocument().DocumentElement, true), status);

            var assertionElement = XmlDocument.DocumentElement[Schemas.SamlConstants.Message.Assertion, Schemas.SamlConstants.AssertionNamespace.OriginalString];
            assertionElement.ParentNode.RemoveChild(assertionElement);

            var encryptedDataElement = new SamlEncryptedXml(EncryptionCertificate.GetRSAPublicKey()).EncryptAassertion(assertionElement);

            var encryptedAssertionElement = XmlDocument.DocumentElement[Schemas.SamlConstants.Message.EncryptedAssertion, Schemas.SamlConstants.AssertionNamespace.OriginalString];
            encryptedAssertionElement.AppendChild(XmlDocument.ImportNode(encryptedDataElement, true));
        }
    }
}
