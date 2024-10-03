using AuthXSSOServiceProvider.Saml.Util;
using System.Xml;

namespace AuthXSSOServiceProvider.Saml
{
    internal static class XmlAttributeExtensions
    {
        public static T GetValueOrNull<T>(this XmlAttribute xmlAttribute)
        {
            return GenericTypeConverter.ConvertValue<T>(xmlAttribute?.Value, xmlAttribute);
        }
    }
}
