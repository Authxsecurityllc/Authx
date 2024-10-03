using System;

namespace AuthXSSOServiceProvider.Saml.Configuration
{
    [Serializable]
    public class SamlConfigurationException : Exception
    {
        public SamlConfigurationException() { }
        public SamlConfigurationException(string message) : base(message) { }
        public SamlConfigurationException(string message, Exception inner) : base(message, inner) { }
        protected SamlConfigurationException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}
