using System;

namespace AuthXSSOServiceProvider.Saml
{
    [Serializable]
    public class SamlBindingException : Exception
    {
        public SamlBindingException() { }
        public SamlBindingException(string message) : base(message) { }
        public SamlBindingException(string message, Exception inner) : base(message, inner) { }
        protected SamlBindingException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context)
            : base(info, context) { }
    }

}
