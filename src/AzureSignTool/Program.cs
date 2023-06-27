using System;
using System.Runtime.InteropServices;
using McMaster.Extensions.CommandLineUtils;

using static AzureSignTool.HRESULT;

namespace AzureSignTool
{
    public class Program
    {
        public static int Main(string[] args)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Console.Error.WriteLine("Azure Sign Tool is only supported on Windows.");
                return E_PLATFORMNOTSUPPORTED;
            }
            var application = new CommandLineApplication<SignApplication>();
            application.ValueParsers.Add(new HashAlgorithmNameValueParser());
            application.Command<SignCommand>("sign", config =>
            {
                config.Description = "Signs a file.";
            });
            application.Command<AwsKms.SignCommand>("aws-sign", config =>
            {
                config.Description = "Signs a file using private key stored in AWS KMS";
            });
            application.Conventions.UseDefaultConventions();
            application.UnrecognizedArgumentHandling = UnrecognizedArgumentHandling.StopParsingAndCollect;
            return application.Execute(args);
        }
    }
}
