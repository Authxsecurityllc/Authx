﻿#if !NETFULL
using System;
using System.Security.Cryptography;

namespace AuthXSSOServiceProvider.Saml.Cryptography
{
    internal class AesGcmDecryptor : ICryptoTransform
    {

        private readonly byte[] key;
        private readonly byte[] nonce;
        private readonly int authenticationTagSizeInBits;

        public AesGcmDecryptor(byte[] key, byte[] nonce, int authenticationTagSizeInBits)
        {
            this.key = key;
            this.nonce = nonce;
            this.authenticationTagSizeInBits = authenticationTagSizeInBits;
        }

        public bool CanReuseTransform => throw new NotImplementedException();

        public bool CanTransformMultipleBlocks => throw new NotImplementedException();

        public int InputBlockSize => throw new NotImplementedException();

        public int OutputBlockSize => throw new NotImplementedException();

        public void Dispose()
        {
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            throw new NotImplementedException();
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            var tagSize = authenticationTagSizeInBits / 8;
            var cipherSize = inputCount - tagSize;

            // "The cipher text contains the IV first, followed by the encrypted octets and finally the Authentication tag."
            // https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM
            var encryptedData = inputBuffer.AsSpan().Slice(inputOffset, inputCount);
            var tag = encryptedData.Slice(encryptedData.Length - tagSize);

            var cipherBytes = encryptedData.Slice(0, cipherSize);

            var plainBytes = cipherSize < 1024
              ? stackalloc byte[cipherSize]
              : new byte[cipherSize];

            using var aesgcm = new AesGcm(key);
            aesgcm.Decrypt(nonce, cipherBytes, tag, plainBytes);

            return plainBytes.ToArray();
        }
    }
}
#endif