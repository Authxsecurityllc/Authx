using System.Xml;
using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml
{
    internal static class XDocumentExtensions
    {
        internal static XmlDocument ToXmlDocument(this XDocument xDocument)
        {
            var xmlDocument = new XmlDocument();
            xmlDocument.XmlResolver = null;
            xmlDocument.PreserveWhitespace = true;
            using (var reader = xDocument.CreateReader())
            {
                reader.Settings.DtdProcessing = DtdProcessing.Prohibit;
                reader.Settings.XmlResolver = null;
                xmlDocument.Load(reader);
            }
            return xmlDocument;
        }

    }
}
