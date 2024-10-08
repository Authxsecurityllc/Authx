﻿using AuthXSSOServiceProvider.Saml.Util;
using System.Xml;

namespace AuthXSSOServiceProvider.Saml
{
    internal static class XmlElementExtensions
    {
        public static T GetValueOrNull<T>(this XmlElement xmlElement)
        {
            return GenericTypeConverter.ConvertValue<T>(xmlElement?.InnerText?.Trim(), xmlElement);
        }

        public static T GetElementOrNull<T>(this XmlElement xmlElement)
        {
            return GenericTypeConverter.ConvertElement<T>(xmlElement);
        }

        internal static XmlDocument ToXmlDocument(this XmlElement xmlElement)
        {
            var xmlDocument = new XmlDocument();
            xmlDocument.XmlResolver = null;
            xmlDocument.PreserveWhitespace = true;
            using (var reader = xmlElement.CreateNavigator().ReadSubtree())
            {
                xmlDocument.Load(reader);
            }
            return xmlDocument;
        }
    }
}
