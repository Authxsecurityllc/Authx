using AuthXSSOServiceProvider.Saml.Schemas;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace AuthXSSOServiceProvider.Saml.Cryptography
{
    public class SamlEncryptedXml : EncryptedXml
    {
        public const string XmlEncKeyAlgorithmRSAOAEPUrl = "http://www.w3.org/2009/xmlenc11#rsa-oaep";

        public RSA EncryptionPublicKey { get; set; }
        public RSA EncryptionPrivateKey { get; set; }

#if !NETFULL
        static SamlEncryptedXml()
        {
            CryptoConfig.AddAlgorithm(typeof(AesGcmAlgorithm), AesGcmAlgorithm.AesGcm256Identifier);
            CryptoConfig.AddAlgorithm(typeof(AesGcmAlgorithm), AesGcmAlgorithm.AesGcm128Identifier);
        }
#endif

        public SamlEncryptedXml(RSA encryptionPublicKey) : base()
        {
            EncryptionPublicKey = encryptionPublicKey;
        }

        public SamlEncryptedXml(XmlDocument document) : base(document)
        {
            if (document == null) throw new ArgumentNullException(nameof(document));
        }

        public SamlEncryptedXml(XmlDocument document, RSA encryptionPrivateKey) : this(document)
        {
            if (encryptionPrivateKey == null) throw new ArgumentNullException(nameof(encryptionPrivateKey));

            EncryptionPrivateKey = encryptionPrivateKey;
        }

        public virtual XmlElement EncryptAassertion(XmlElement assertionElement)
        {
            using (var encryptionAlgorithm = Aes.Create())
            {
                encryptionAlgorithm.KeySize = 256;

                var encryptedData = new EncryptedData
                {
                    Type = XmlEncElementUrl,
                    EncryptionMethod = new EncryptionMethod(XmlEncAES256Url),
                    KeyInfo = new KeyInfo()
                };
                encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(new EncryptedKey
                {
                    EncryptionMethod = new EncryptionMethod(XmlEncRSAOAEPUrl),
                    CipherData = new CipherData(EncryptKey(encryptionAlgorithm.Key, EncryptionPublicKey, true))
                }));

                var encryptedXml = new EncryptedXml();
                encryptedData.CipherData.CipherValue = encryptedXml.EncryptData(assertionElement, encryptionAlgorithm, false);

                return encryptedData.GetXml();
            }
        }

        public override byte[] GetDecryptionIV(EncryptedData encryptedData, string symmetricAlgorithmUri)
        {
            if (encryptedData is null)
            {
                throw new ArgumentNullException(nameof(encryptedData));
            }

#if !NETFULL

            var aesGcmSymmetricAlgorithmUri = symmetricAlgorithmUri ?? encryptedData.EncryptionMethod?.KeyAlgorithm;
            if (aesGcmSymmetricAlgorithmUri == AesGcmAlgorithm.AesGcm128Identifier || aesGcmSymmetricAlgorithmUri == AesGcmAlgorithm.AesGcm256Identifier)
            {
                int initBytesSize = 12;
                byte[] iv = new byte[initBytesSize];
                Buffer.BlockCopy(encryptedData.CipherData.CipherValue, 0, iv, 0, iv.Length);
                return iv;
            }
#endif

            return base.GetDecryptionIV(encryptedData, symmetricAlgorithmUri);
        }

        public override byte[] DecryptEncryptedKey(EncryptedKey encryptedKey)
        {
            if (encryptedKey.EncryptionMethod.KeyAlgorithm == XmlEncKeyAlgorithmRSAOAEPUrl)
            {
                return EncryptionPrivateKey.Decrypt(encryptedKey.CipherData.CipherValue, GetEncryptionPadding(encryptedKey));
            }
            else
            {
                return DecryptKey(encryptedKey.CipherData.CipherValue, EncryptionPrivateKey, (encryptedKey.EncryptionMethod != null) && (encryptedKey.EncryptionMethod.KeyAlgorithm == XmlEncRSAOAEPUrl));
            }
        }

        private static RSAEncryptionPadding GetEncryptionPadding(EncryptedKey encryptedKey)
        {
            var xmlElement = encryptedKey.GetXml();
            var nsm = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
            nsm.AddNamespace("enc", XmlEncNamespaceUrl);
            nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            var digestMethodElement = xmlElement.SelectSingleNode("enc:EncryptionMethod/ds:DigestMethod", nsm) as XmlElement;
            if (digestMethodElement != null)
            {
                var method = digestMethodElement.GetAttribute("Algorithm");
                switch (method)
                {
                    case SamlSecurityAlgorithms.Sha1Digest:
                        return RSAEncryptionPadding.OaepSHA1;
                    case SamlSecurityAlgorithms.Sha256Digest:
                        return RSAEncryptionPadding.OaepSHA256;
                    case SamlSecurityAlgorithms.Sha384Digest:
                        return RSAEncryptionPadding.OaepSHA384;
                    case SamlSecurityAlgorithms.Sha512Digest:
                        return RSAEncryptionPadding.OaepSHA512;
                }
            }

            return RSAEncryptionPadding.OaepSHA256;
        }
    }
}
