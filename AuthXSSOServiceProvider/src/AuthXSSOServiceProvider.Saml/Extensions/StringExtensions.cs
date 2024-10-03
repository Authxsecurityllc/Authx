using System.IO;
using System.Xml;

namespace AuthXSSOServiceProvider.Saml
{
    public static class StringExtensions
    {
        public static XmlDocument ToXmlDocument(this string xml)
        {
            using (var stringReader = new StringReader(xml))
            using (var xmlReader = XmlReader.Create(stringReader, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }))
            {
                var xmlDocument = new XmlDocument();
                xmlDocument.XmlResolver = null;
                xmlDocument.PreserveWhitespace = true;
                xmlDocument.Load(xmlReader);
                return xmlDocument;
            }
        }
    }
}
