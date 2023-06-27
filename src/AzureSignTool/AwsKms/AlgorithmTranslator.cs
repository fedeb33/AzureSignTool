using System;
using System.Security.Cryptography;
using Amazon.KeyManagementService;

namespace AzureSignTool.AwsKms
{
    internal static class AlgorithmTranslator
    {
        public static SigningAlgorithmSpec Parse(HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            return hashAlgorithm.Name switch
            {
                "SHA256" => padding.Mode switch
                {
                    RSASignaturePaddingMode.Pkcs1 => SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256,
                    RSASignaturePaddingMode.Pss => SigningAlgorithmSpec.RSASSA_PSS_SHA_256,
                    _ => throw new Exception($"Combination of hash algorithm and padding not supported: {hashAlgorithm} {padding}"),
                },
                "SHA384" => padding.Mode switch
                {
                    RSASignaturePaddingMode.Pkcs1 => SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384,
                    RSASignaturePaddingMode.Pss => SigningAlgorithmSpec.RSASSA_PSS_SHA_384,
                    _ => throw new Exception($"Combination of hash algorithm and padding not supported: {hashAlgorithm} {padding}"),
                },
                "SHA512" => padding.Mode switch
                {
                    RSASignaturePaddingMode.Pkcs1 => SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512,
                    RSASignaturePaddingMode.Pss => SigningAlgorithmSpec.RSASSA_PSS_SHA_512,
                    _ => throw new Exception($"Combination of hash algorithm and padding not supported: {hashAlgorithm} {padding}"),
                },
                _ => throw new Exception($"Combination of hash algorithm and padding not supported: {hashAlgorithm} {padding}"),
            };
        }

        public static EncryptionAlgorithmSpec Parse(RSAEncryptionPadding padding)
        {
            return padding switch
            {
                { Mode: RSAEncryptionPaddingMode.Oaep, OaepHashAlgorithm.Name: "SHA256" } => EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256,
                _ => throw new Exception($"Encryption padding is not supported: {padding}"),
            };
        }
    }
}
