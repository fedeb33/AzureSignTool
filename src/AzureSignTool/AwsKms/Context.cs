using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Amazon;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using Azure.Security.KeyVault.Keys;

namespace AzureSignTool.AwsKms
{
    public class Context
    {
        private readonly AmazonKeyManagementServiceClient cryptographyClient;

        public string KeyId { get; }

        public X509Certificate2 Certificate { get; }

        public JsonWebKey Key { get; }

        //
        // Summary:
        //     Returns true if properly constructed. If default, then false.
        public bool IsValid => cryptographyClient != null;

        //
        // Summary:
        //     Creates a new AWS KMS context.
        public Context(AWSCredentials credentials, RegionEndpoint region, string keyId, X509Certificate2 publicCertificate)
        {
            if (credentials == null)
                throw new ArgumentNullException(nameof(credentials));

            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentNullException(nameof(keyId));

            KeyId = keyId;
            Certificate = publicCertificate ?? throw new ArgumentNullException(nameof(publicCertificate));

            cryptographyClient = new AmazonKeyManagementServiceClient(credentials, region);
            var keyAlgorithm = publicCertificate.GetKeyAlgorithm();
            switch (keyAlgorithm)
            {
                case "1.2.840.113549.1.1.1":
                    {
                        using (var rsaProvider = publicCertificate.GetRSAPublicKey())
                        {
                            Key = new JsonWebKey(rsaProvider);
                        }

                        break;
                    }
                case "1.2.840.10045.2.1":
                    {
                        using (var ecdsa = publicCertificate.GetECDsaPublicKey())
                        {
                            Key = new JsonWebKey(ecdsa);
                        }

                        break;
                    }
                default:
                    throw new NotSupportedException("Certificate algorithm '" + keyAlgorithm + "' is not supported.");
            }
        }

        internal byte[] SignDigest(byte[] digest, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            var signRequest = new SignRequest
            {
                KeyId = KeyId,
                Message = new MemoryStream(digest),
                MessageType = MessageType.DIGEST,
                SigningAlgorithm = AlgorithmTranslator.Parse(hashAlgorithm, padding),
            };
            var result = cryptographyClient.SignAsync(signRequest).Result;
            return result.Signature.ToArray();
        }

        internal byte[] DecryptData(byte[] cipherText, RSAEncryptionPadding padding)
        {
            var decryptRequest = new DecryptRequest
            {
                KeyId = KeyId,
                CiphertextBlob = new MemoryStream(cipherText),
                EncryptionAlgorithm = AlgorithmTranslator.Parse(padding),
            };
            return cryptographyClient.DecryptAsync(decryptRequest).Result.Plaintext.ToArray();
        }
    }
}
