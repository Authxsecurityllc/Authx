using System.Security.Cryptography;

namespace AuthXSSOServiceProvider.Saml.Util
{
    internal static class RandomGenerator
    {
        private static readonly RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create();

        public static byte[] GenerateArtifactMessageHandle()
        {
            return GenerateBytes(20);
        }

        public static byte[] GenerateBytes(int length)
        {
            var bytes = new byte[length];
            randomNumberGenerator.GetNonZeroBytes(bytes);
            return bytes;
        }

    }
}
