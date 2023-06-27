using System;
using System.IO;
using System.Security.Cryptography;

namespace AzureSignTool.AwsKms
{
    public sealed class RSA : System.Security.Cryptography.RSA
    {
        private readonly Context context;

        private System.Security.Cryptography.RSA publicKey;

        public RSA(Context context)
        {
            if (!context.IsValid)
            {
                throw new ArgumentException("Must not be the default", nameof(context));
            }

            this.context = context;
            publicKey = context.Key.ToRSA();
            KeySizeValue = publicKey.KeySize;
            LegalKeySizesValue = new KeySizes[1]
            {
                new KeySizes(publicKey.KeySize, publicKey.KeySize, 0)
            };
        }

        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            CheckDisposed();
            if (padding.Mode != 0)
            {
                throw new CryptographicException("Unsupported padding mode");
            }

            try
            {
                return context.SignDigest(hash, hashAlgorithm, padding);
            }
            catch (Exception inner)
            {
                throw new CryptographicException("Error calling AWS KMS", inner);
            }
        }

        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            CheckDisposed();
            return publicKey.VerifyHash(hash, signature, hashAlgorithm, padding);
        }

        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            CheckDisposed();
            using var hashAlgorithm2 = Create(hashAlgorithm);
            return hashAlgorithm2.ComputeHash(data, offset, count);
        }

        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
        {
            CheckDisposed();
            using var hashAlgorithm2 = Create(hashAlgorithm);
            return hashAlgorithm2.ComputeHash(data);
        }

        public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
        {
            CheckDisposed();
            try
            {
                return context.DecryptData(data, padding);
            }
            catch (Exception inner)
            {
                throw new CryptographicException("Error calling AWS KMS", inner);
            }
        }

        public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
        {
            CheckDisposed();
            return publicKey.Encrypt(data, padding);
        }

        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            CheckDisposed();
            if (includePrivateParameters)
            {
                throw new CryptographicException("Private keys cannot be exported by this provider");
            }

            return publicKey.ExportParameters(includePrivateParameters);
        }

        public override void ImportParameters(RSAParameters parameters)
        {
            throw new NotSupportedException();
        }

        private void CheckDisposed()
        {
            if (publicKey == null)
            {
                throw new ObjectDisposedException("RSA is disposed");
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                publicKey?.Dispose();
                publicKey = null;
            }

            base.Dispose(disposing);
        }

        private static HashAlgorithm Create(HashAlgorithmName algorithm)
        {
            if (algorithm == HashAlgorithmName.SHA256)
            {
                return SHA256.Create();
            }

            if (algorithm == HashAlgorithmName.SHA384)
            {
                return SHA384.Create();
            }

            if (algorithm == HashAlgorithmName.SHA512)
            {
                return SHA512.Create();
            }

            throw new NotSupportedException("The specified algorithm is not supported.");
        }
    }
}
