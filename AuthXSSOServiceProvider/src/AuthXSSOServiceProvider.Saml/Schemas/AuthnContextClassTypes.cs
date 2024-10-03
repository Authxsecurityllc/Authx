
using System;
namespace AuthXSSOServiceProvider.Saml.Schemas
{
    public static class AuthnContextClassTypes
    {
        public static Uri InternetProtocol = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol");

        public static Uri InternetProtocolPassword = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword");

        public static Uri Kerberos = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos");

        public static Uri IntegratedWindowsAuthentication = new Uri("urn:federation:authentication:windows");

        public static Uri MobileOneFactorUnregistered = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorUnregistered");

        public static Uri MobileTwoFactorUnregistered = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered");

        public static Uri MobileOneFactorContract = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorContract");

        public static Uri MobileTwoFactorContract = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract");
    
        public static Uri UserNameAndPassword = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");

        public static Uri PasswordProtectedTransport = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

        public static Uri SecureRemotePassword = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:SecureRemotePassword");

        public static Uri PreviousSession = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession");

        public static Uri X509Certificate = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:X509");

        public static Uri PublicKeyPgp = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:PGP");

        public static Uri PublicKeySpki = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:SPKI");

        public static Uri PublicKeyXmlDigitalDignature = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:XMLDSig");

        public static Uri Smartcard = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard");

        public static Uri SmartcardPKI = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI");

        public static Uri SoftwarePki = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI");

        public static Uri Telephony = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:Telephony");

        public static Uri TelephonyNomad = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:NomadTelephony");

        public static Uri TelephonyPersonal = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:PersonalTelephony");

        public static Uri TelephonyAuthenticated = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:AuthenticatedTelephony");

        public static Uri TransportLayerSecurityClient = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient");

        public static Uri TimeSyncToken = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken");       

        public static Uri Unspecified = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified");

    }
}
