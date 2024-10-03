using System.Xml.Linq;

namespace AuthXSSOServiceProvider.Saml.Schemas.Conditions
{
    public interface ICondition
    {
        XElement ToXElement();
    }
}