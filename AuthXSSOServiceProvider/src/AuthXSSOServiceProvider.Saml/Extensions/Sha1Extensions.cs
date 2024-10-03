using System.Security.Cryptography;
using System.Text;

namespace AuthXSSOServiceProvider.Saml
{
    public static class Sha1Extensions
    {
        private static readonly SHA1 sha1 = SHA1.Create();

        public static byte[] ComputeSha1Hash(this string value) 
        {
            return sha1.ComputeHash(Encoding.UTF8.GetBytes(value));
        }


    }
}
