using System;

namespace AuthXSSOServiceProvider.Saml
{
    [Serializable]
    public class SamlRequestException : Exception
    {
        public SamlRequestException() { }
        public SamlRequestException(string message) : base(message) { }
        public SamlRequestException(string message, Exception inner) : base(message, inner) { }
        protected SamlRequestException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context)
            : base(info, context) { }
    }
}
