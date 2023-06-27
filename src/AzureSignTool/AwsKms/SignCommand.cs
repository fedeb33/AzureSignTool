using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Amazon;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using AzureSign.Core;
using McMaster.Extensions.CommandLineUtils;
using McMaster.Extensions.CommandLineUtils.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using static AzureSignTool.HRESULT;

namespace AzureSignTool.AwsKms
{
    internal sealed class SignCommand
    {
        [Option("--profile", "Named profile to authenticate with AWS.", CommandOptionType.SingleValue), Required]
        public string Profile { get; set; }

        [Option("--region", "AWS region where the key belong to.", CommandOptionType.SingleValue), Required]
        public string Region { get; set; }

        [Option("--key-id", "Identifies an asymmetric KMS key. To specify a KMS key, use its key ID, key ARN, alias name, or alias ARN.", CommandOptionType.SingleValue), Required]
        public string KeyId { get; set; }

        [Option("--certificate", "Certificate associated to the private key stored in AWS KMS.", CommandOptionType.SingleValue), Required]
        public string Certificate { get; set; }

        [Option("-d | --description", "Provide a description of the signed content.", CommandOptionType.SingleValue)]
        public string Description { get; set; }

        [Option("-du | --description-url", "Provide a URL with more information about the signed content.", CommandOptionType.SingleValue), UriValidator]
        public string DescriptionUri { get; set; }

        [Option("-tr | --timestamp-rfc3161", "Specifies the RFC 3161 timestamp server's URL. If this option (or -t) is not specified, the signed file will not be timestamped.", CommandOptionType.SingleValue), UriValidator]
        public (bool Present, string Uri) Rfc3161Timestamp { get; set; }

        [Option("-td | --timestamp-digest", "Used with the -tr switch to request a digest algorithm used by the RFC 3161 timestamp server.", CommandOptionType.SingleValue)]
        [AllowedValues("sha1", "sha256", "sha384", "sha512", IgnoreCase = true)]
        public HashAlgorithmName TimestampDigestAlgorithm { get; set; } = HashAlgorithmName.SHA256;

        [Option("-fd | --file-digest", "The digest algorithm to hash the file with.", CommandOptionType.SingleValue)]
        [AllowedValues("sha1", "sha256", "sha384", "sha512", IgnoreCase = true)]
        public HashAlgorithmName FileDigestAlgorithm { get; set; } = HashAlgorithmName.SHA256;

        [Option("-t | --timestamp-authenticode", "Specify the timestamp server's URL. If this option is not present, the signed file will not be timestamped.", CommandOptionType.SingleValue), UriValidator]
        public (bool Present, string Uri) AuthenticodeTimestamp { get; set; }

        [Option("-ac | --additional-certificates", "Specify one or more certificates to include in the public certificate chain.", CommandOptionType.MultipleValue), FileExists]
        public string[] AdditionalCertificates { get; set; } = Array.Empty<string>();

        [Option("-v | --verbose", "Include additional output.", CommandOptionType.NoValue)]
        public bool Verbose { get; set; }

        [Option("-q | --quiet", "Do not print any output to the console.", CommandOptionType.NoValue)]
        public bool Quiet { get; set; }

        [Option("-ph | --page-hashing", "Generate page hashes for executable files if supported.", CommandOptionType.NoValue)]
        public bool PageHashing { get; set; }

        [Option("-nph | --no-page-hashing", "Suppress page hashes for executable files if supported.", CommandOptionType.NoValue)]
        public bool NoPageHashing { get; set; }

        [Option("-coe | --continue-on-error", "Continue signing multiple files if an error occurs.", CommandOptionType.NoValue)]
        public bool ContinueOnError { get; set; }

        [Option("-ifl | --input-file-list", "A path to a file that contains a list of files, one per line, to sign.", CommandOptionType.SingleValue), FileExists]
        public string InputFileList { get; set; }

        [Option("-mdop | --max-degree-of-parallelism", "The maximum number of concurrent signing operations.", CommandOptionType.SingleValue), Range(-1, int.MaxValue)]
        public int? MaxDegreeOfParallelism { get; set; }

        [Option("--colors", "Enable color output on the command line.", CommandOptionType.NoValue)]
        public bool Colors { get; set; } = false;

        [Option("-s | --skip-signed", "Skip files that are already signed.", CommandOptionType.NoValue)]
        public bool SkipSignedFiles { get; set; } = false;

        // We manually validate the file's existance with the --input-file-list. Don't validate here.
        [Argument(0, "file", "The path to the file.")]
        public string[] Files { get; set; } = Array.Empty<string>();

        private HashSet<string> _allFiles;
        public HashSet<string> AllFiles
        {
            get
            {
                if (_allFiles == null)
                {
                    _allFiles = new HashSet<string>(Files);
                    if (!string.IsNullOrWhiteSpace(InputFileList))
                    {
                        _allFiles.UnionWith(File.ReadLines(InputFileList).Where(s => !string.IsNullOrWhiteSpace(s)));
                    }
                }
                return _allFiles;
            }
        }

        public LogLevel LogLevel
        {
            get
            {
                if (Quiet)
                {
                    return LogLevel.Critical;
                }
                else if (Verbose)
                {
                    return LogLevel.Trace;
                }
                else
                {
                    return LogLevel.Information;
                }
            }
        }

        private ValidationResult OnValidate(ValidationContext context, CommandLineContext appContext)
        {
            if (PageHashing && NoPageHashing)
            {
                return new ValidationResult("Cannot use '--page-hashing' and '--no-page-hashing' options together.", new[] { nameof(NoPageHashing), nameof(PageHashing) });
            }
            if (Quiet && Verbose)
            {
                return new ValidationResult("Cannot use '--quiet' and '--verbose' options together.", new[] { nameof(NoPageHashing), nameof(PageHashing) });
            }
            if (Rfc3161Timestamp.Present && AuthenticodeTimestamp.Present)
            {
                return new ValidationResult("Cannot use '--timestamp-rfc3161' and '--timestamp-authenticode' options together.", new[] { nameof(Rfc3161Timestamp), nameof(AuthenticodeTimestamp) });
            }
            if (AllFiles.Count == 0)
            {
                return new ValidationResult("At least one file must be specified to sign.");
            }
            foreach (var file in AllFiles)
            {
                if (!File.Exists(file))
                {
                    return new ValidationResult($"File '{file}' does not exist.");
                }
            }
            return ValidationResult.Success;
        }

        public int OnValidationError(ValidationResult result, CommandLineApplication<SignCommand> command, IConsole console)
        {
            console.ForegroundColor = ConsoleColor.Red;
            console.Error.WriteLine(result.ErrorMessage);
            console.ResetColor();
            command.ShowHint();
            return E_INVALIDARG;
        }

        private void ConfigureLogging(ILoggingBuilder builder)
        {
            builder.AddSimpleConsole(console =>
            {
                console.IncludeScopes = true;
                console.ColorBehavior = Colors ? LoggerColorBehavior.Enabled : LoggerColorBehavior.Disabled;
            });

            builder.SetMinimumLevel(LogLevel);
        }

        public async Task<int> OnExecuteAsync(CommandLineApplication app, IConsole console)
        {
            using (var loggerFactory = LoggerFactory.Create(ConfigureLogging))
            {
                var logger = loggerFactory.CreateLogger<SignCommand>();

                X509Certificate2 certificate;
                switch (GetCertificate(Certificate, logger))
                {
                    case ErrorOr<X509Certificate2>.Ok d:
                        certificate = d.Value;
                        break;
                    case ErrorOr<X509Certificate2>.Err err:
                        logger.LogError(err.Error, err.Error.Message);
                        return E_INVALIDARG;
                    default:
                        logger.LogError("Failed to load certificate.");
                        return E_INVALIDARG;
                }
                logger.LogInformation($"Certificate subject: {certificate.Subject}");

                X509Certificate2Collection certificates;
                switch (GetAdditionalCertificates(AdditionalCertificates, logger))
                {
                    case ErrorOr<X509Certificate2Collection>.Ok d:
                        certificates = d.Value;
                        break;
                    case ErrorOr<X509Certificate2Collection>.Err err:
                        logger.LogError(err.Error, err.Error.Message);
                        return E_INVALIDARG;
                    default:
                        logger.LogError("Failed to include additional certificates.");
                        return E_INVALIDARG;
                }

                TimeStampConfiguration timeStampConfiguration;
                if (Rfc3161Timestamp.Present)
                {
                    timeStampConfiguration = new TimeStampConfiguration(Rfc3161Timestamp.Uri, TimestampDigestAlgorithm, TimeStampType.RFC3161);
                }
                else if (AuthenticodeTimestamp.Present)
                {
                    logger.LogWarning("Authenticode timestamps should only be used for compatibility purposes. RFC3161 timestamps should be used.");
                    timeStampConfiguration = new TimeStampConfiguration(AuthenticodeTimestamp.Uri, default, TimeStampType.Authenticode);
                }
                else
                {
                    logger.LogWarning("Signatures will not be timestamped. Signatures will become invalid when the signing certificate expires.");
                    timeStampConfiguration = TimeStampConfiguration.None;
                }

                bool? performPageHashing = null;
                if (PageHashing)
                {
                    performPageHashing = true;
                }
                if (NoPageHashing)
                {
                    performPageHashing = false;
                }

                int failed = 0, succeeded = 0;
                var cancellationSource = new CancellationTokenSource();
                console.CancelKeyPress += (_, e) =>
                {
                    e.Cancel = true;
                    cancellationSource.Cancel();
                    logger.LogInformation("Cancelling signing operations.");
                };
                var options = new ParallelOptions();
                if (MaxDegreeOfParallelism.HasValue)
                {
                    options.MaxDegreeOfParallelism = MaxDegreeOfParallelism.Value;
                }

                logger.LogTrace("Creating context");

                var credentials = GetCredentialsFromProfile(Profile);
                var region = GetRegion(Region);

                using (var keyVault = new RSA(new Context(credentials, region, KeyId, certificate)))
                using (var signer = new AuthenticodeKeyVaultSigner(keyVault, certificate, FileDigestAlgorithm, timeStampConfiguration, certificates))
                {
                    Parallel.ForEach(AllFiles, options, () => (succeeded: 0, failed: 0), (filePath, pls, state) =>
                    {
                        if (cancellationSource.IsCancellationRequested)
                        {
                            pls.Stop();
                        }
                        if (pls.IsStopped)
                        {
                            return state;
                        }
                        using (logger.BeginScope("File: {Id}", filePath))
                        {
                            logger.LogInformation("Signing file.");

                            if (SkipSignedFiles && IsSigned(filePath))
                            {
                                logger.LogInformation("Skipping already signed file.");
                                return (state.succeeded + 1, state.failed);
                            }

                            var result = signer.SignFile(filePath, Description, DescriptionUri, performPageHashing, logger);
                            switch (result)
                            {
                                case COR_E_BADIMAGEFORMAT:
                                    logger.LogError("The Publisher Identity in the AppxManifest.xml does not match the subject on the certificate.");
                                    break;
                                case TRUST_E_SUBJECT_FORM_UNKNOWN:
                                    logger.LogError("The file cannot be signed because it is not a recognized file type for signing or it is corrupt.");
                                    break;
                            }

                            if (result == S_OK)
                            {
                                logger.LogInformation("Signing completed successfully.");
                                return (state.succeeded + 1, state.failed);
                            }
                            else
                            {
                                logger.LogError($"Signing failed with error {result:X2}.");
                                if (!ContinueOnError || AllFiles.Count == 1)
                                {
                                    logger.LogInformation("Stopping file signing.");
                                    pls.Stop();
                                }

                                return (state.succeeded, state.failed + 1);
                            }
                        }
                    }, result =>
                    {
                        Interlocked.Add(ref failed, result.failed);
                        Interlocked.Add(ref succeeded, result.succeeded);
                    });
                }
                logger.LogInformation($"Successful operations: {succeeded}");
                logger.LogInformation($"Failed operations: {failed}");
                if (failed > 0 && succeeded == 0)
                {
                    return E_ALL_FAILED;
                }
                else if (failed > 0)
                {
                    return S_SOME_SUCCESS;
                }
                else
                {
                    return S_OK;
                }
            }
        }

        private static bool IsSigned(string filePath)
        {
            try
            {
                _ = X509Certificate.CreateFromSignedFile(filePath);
                return true;
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        private static ErrorOr<X509Certificate2> GetCertificate(string path, ILogger logger)
        {
            var type = X509Certificate2.GetCertContentType(path);
            switch (type)
            {
                case X509ContentType.Cert:
                case X509ContentType.Authenticode:
                case X509ContentType.SerializedCert:
                    var certificate = new X509Certificate2(path);
                    logger.LogTrace($"Certificate {certificate.Thumbprint} was read successfully.");
                    return certificate;
                default:
                    return new Exception($"Specified file {path} is not a public valid certificate.");
            }
        }

        private static ErrorOr<X509Certificate2Collection> GetAdditionalCertificates(IEnumerable<string> paths, ILogger logger)
        {
            var collection = new X509Certificate2Collection();
            try
            {
                foreach (var path in paths)
                {

                    var result = GetCertificate(path, logger);
                    switch (result)
                    {
                        case ErrorOr<X509Certificate2>.Ok r:
                            collection.Add(r.Value);
                            break;
                        case ErrorOr<X509Certificate2>.Err r:
                            return r.Error;
                    }
                }
            }
            catch (CryptographicException e)
            {
                logger.LogError(e, "An exception occurred while including an additional certificate.");
                return e;
            }

            return collection;
        }

        private static AWSCredentials GetCredentialsFromProfile(string profile)
        {
            var sharedFile = new SharedCredentialsFile();
            sharedFile.TryGetProfile(profile, out var basicProfile);
            AWSCredentialsFactory.TryGetAWSCredentials(basicProfile, sharedFile, out var awsCredentials);
            return awsCredentials;
        }

        private static RegionEndpoint GetRegion(string region)
        {
            return RegionEndpoint.GetBySystemName(region);
        }
    }
}
