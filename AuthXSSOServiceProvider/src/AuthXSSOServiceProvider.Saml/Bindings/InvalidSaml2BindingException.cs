using System;

namespace AuthXSSOServiceProvider.Saml
{
    [Serializable]
    public class InvalidSamlBindingException : Exception
    {
        public InvalidSamlBindingException() { }
        public InvalidSamlBindingException(string message) : base(message) { }
        public InvalidSamlBindingException(string message, Exception inner) : base(message, inner) { }
        protected InvalidSamlBindingException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context)
            : base(info, context) { }
    }
}
