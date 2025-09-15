using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace MiniCA;

// This started as a C# port of the MiniCA tool (https://github.com/jsha/minica), using GitHub Copilot with a few manual "tweaks". It morphed into something bigger.
// The original code is written in Go and licensed under the MIT License. Please take a look at the original repository, if only to give the author a star for their work.

// Sure, it looks NOTHING like the original, but the sentiment is the same, and I did "port" it initially rather than just write my own version.

// I have added some extra features, which are shared for the greater good:
// - This creates intermediate CAs. The original only created a root CA. There is a reason for this - CAs are meant to be kept very secure, and not used for signing leaf certs.
// - It enables client certificates (so you can do mutual TLS authentication). I use these for single sign-on (SSO) in some of my projects.
// - It includes certificate organisation and unit (because I wanted them present).
// - UPN for client certificates is supported.
// - The original added a suffix. I've kept it, but made it optional.
// - There are text file instructions saved for adding using certutil. In my own app the pipeline does this for me, but I thought it might be useful for others.
// - It creates a full chain file (because some systems need it), like nginx - includes CA + intermediate CA certs. Again, I use this in my own projects, and it works!
// - It will create P12 files for client certificates. For example in SSO, the p12 file can be imported into a browser to enable client cert auth.
// - There is more validation of some CA attributes implemented. I've expanded the validation to cover more edge cases.

static class Program
{
    /// <summary>
    /// Entry point for the MiniCA application.
    /// </summary>
    /// <param name="args"></param>
    static void Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8; // to support the certificate chain output
        ShowLogo(args);

        try
        {
            var options = ParseArgs(args);

            // If no arguments or invalid arguments are provided, show usage and exit
            if (options == null || !OptionsAreValid(options))
            {
                ShowUsage();
                Environment.Exit(1);
            }

            // there are times when you want to be very sure you passed the correct options, this helps.
            EchoOptionsToConsole(options);

            // Run the MiniCA tool with the provided options
            MiniCATool.CreateSpecifiedCertificate(options);

            // Exit(0) indicates success
        }
        catch (Exception ex)
        {
            Log.Error("An unexpected error occurred whilst generating a certificate.");
            Log.Error(ex.Message);
            Environment.Exit(1);
        }
    }

    /// <summary>
    /// We echo the options to the console so the user can see what we are doing,
    /// as some of these may be defaults...
    /// </summary>
    /// <param name="options"></param>
    private static void EchoOptionsToConsole(MinicaOptions options)
    {
        bool isClientCert = !string.IsNullOrEmpty(options.User);

        // Unambiguously echo the options to the console. These are what we used to generate the cert.
        Log.Info("Generation Options:");
        Log.Info($"  ROOT CA");
        Log.Info($"    Name:              {options.RootCAName}");
        Log.Info($"    Key Filename:      {options.RootCAKeyFilePath}");
        Log.Info($"    Cert Filename:     {options.RootCACertFilePath}");
        Log.Info($"    Algorithm:         {options.CaAlg}");
        Log.Info($"    Expiry:            {options.CaExpiry}");

        // if we are creating an intermediate CA, show the details
        if (options.CreateIntermediateCA)
        {
            Log.Info($"  INTERMEDIATE CA");
            Log.Info($"    Key Filename:      {options.IntermediateCAKeyFilePath}");
            Log.Info($"    Cert Filename:     {options.IntermediateCACertFilePath}");
            Log.Info($"    Expiry:            {options.IntermediateCaExpiry}");
        }
        else
        {
            Log.Info($"  INTERMEDIATE CA:      OFF, leaf certs signed directly by the Root CA (not recommended)");
        }

        if (!string.IsNullOrEmpty(options.Domains))
            Log.Info($"  Domains:             {options.Domains}");
        
        if (!string.IsNullOrEmpty(options.IpAddresses))
            Log.Info($"  IP Addresses:        {options.IpAddresses}");

        if (isClientCert)
        {
            Log.Info($"  CLIENT AUTH");
            Log.Info($"    User:              {options.User}");
            Log.Info($"    P12 Password:      {options.P12Password}");
            Log.Info($"    P12 FilePath:      {options.LeafP12FilePath}");
        }
        
        Log.Info($"    Expiry:            {options.LeafCertExpiry}");

        if (!string.IsNullOrEmpty(options.Organisation))
            Log.Info($"  Organisation:        {options.Organisation}");

        if (!string.IsNullOrEmpty(options.OrganisationalUnit))
            Log.Info($"  Organisational Unit: {options.OrganisationalUnit}");

        if (!string.IsNullOrEmpty(options.Country))
            Log.Info($"  Country:             {options.Country}");

        Log.Info($"  Random Suffix:       {(options.SuffixRandomExtensionToCAName?"yes":"no")}");

        Log.Info("");
    }

    /// <summary>
    /// Outputs the MiniCA logo to the console.
    /// </summary>
    private static void ShowLogo(string[] args)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Log.Info(@"   _____  .__       .___________     _____   ");
        Log.Info(@"  /     \ |__| ____ |__\_   ___ \   /  _  \  ");
        Log.Info(@" /  \ /  \|  |/    \|  /    \  \/  /  /_\  \     MiniCA - A simple Certificate Authority tool");
        Log.Info(@"/    Y    \  |   |  \  \     \____/    |    \    Based on https://github.com/jsha/minica (GoLang)");
        Log.Info(@"\____|__  /__|___|  /__|\______  /\____|__  /");
        Log.Info(@"        \/        \/           \/         \/ ");
        Console.ResetColor();

        Log.Info("");

        if (args.Length == 0)
        {
            Log.Error("No arguments provided.");
            return;
        }

        Log.Info("Arguments: ");

        // output arguments, quoting any that contain spaces
        foreach (string arg in args)
        {
            Log.Info(arg.Contains(' ') ? $"\"{arg}\" " : $"{arg} ", false);
        }

        Log.Info("\n"); // 2x new line, one from the loop, one here.
    }

    /// <summary>
    /// Validates the options provided.
    /// </summary>
    /// <param name="options"></param>
    /// <returns></returns>
    internal static bool OptionsAreValid(MinicaOptions options)
    {
        // validate CA algorithm
        if (!options.IsValidAlgorithm())
        {
            Log.Error($"Error: Invalid CA algorithm \"{options.CaAlg}\". Must be either 'ecdsa' or 'rsa'.");
            return false;
        }

        if (!options.IsValidCAName(out string reason)) // validate CA name
        {
            Log.Error(reason);
            return false;
        }

        if (!options.AreDomainsValid(out string domainInError))
        {
            Log.Error($"\"{domainInError}\" is not a valid domain. e.g. *.mydomain.com for a wildcard, or www.mydomain.com");
            return false;
        }

        if (!options.AreIpAddressesValid(out string ipInError))
        {
            Log.Error($"\"{ipInError}\" is not a valid IP V4 address.");
            return false;
        }

        // if User is specified, it must be a valid UPN (basic validation)
        if (!options.IsValidUser())
        {
            Log.Error($"\"{options.User}\" is not a valid User Principal Name (UPN).");
            return false;
        }

        // validate the path we are going to write the private key to is valid
        if (!options.IsValidKeyFilePath())
        {
            Log.Error($"Error: The private key file-path does not exist.");
            return false;
        }

        // validate the path we are going to write the certificate to is valid
        if (!options.IsValidCertFilePath())
        {
            Log.Error($"Error: The certificate file-path does not exist.");
            return false;
        }

        // validate CaFileName is safe to use as a file name
        if (!options.IsValidCaFileName(out string errorMessage))
        {
            Log.Error(errorMessage);
            return false;
        }

        // validate organisation if entered is valid for a certificate O= field
        if (!options.IsValidOrganisation())
        {
            Log.Error($"Error: Organisation contains invalid characters. Only alphanumeric characters, spaces, and . , ' - & ( ) are allowed. Max 64 chars. You provided: {options.Organisation}");
            return false;
        }

        // validate organisation unit if entered is valid for a certificate OU= field
        if (!options.IsValidOrganisationalUnit())
        {
            Log.Error($"Error: Organisational Unit contains invalid characters. Only alphanumeric characters, spaces, and . , ' - & ( ) are allowed. Max 64 chars. You provided: {options.OrganisationalUnit}");
            return false;
        }

        // validate country if entered is valid for a certificate C= field (must be exactly 2 letters)
        if (!options.IsValidCountry())
        {
            Log.Error($"Error: Country must be exactly 2 letters (ISO 3166-1 alpha-2 code). You provided: {options.Country}");
            return false;
        }

        if(!MinicaOptions.IsValidExpiryString(options.CaExpiry))
        {
            Log.Error($"Error: The Root CA expiry value is invalid. It must be a number followed by 'y' (years), 'm' (months) or 'd' (days). e.g. 20y = 20 years, 240m = 20 years, 730d = 2 years. You provided: {options.CaExpiry}");
            return false;
        }

        if(!MinicaOptions.IsValidExpiryString(options.IntermediateCaExpiry))
        {
            Log.Error($"Error: The Intermediate CA expiry value is invalid. It must be a number followed by 'y' (years), 'm' (months) or 'd' (days). e.g. 10y = 10 years, 120m = 10 years, 3650d = 10 years. You provided: {options.IntermediateCaExpiry}");
            return false;
        }

        if(!MinicaOptions.IsValidExpiryString(options.LeafCertExpiry))
        {
            Log.Error($"Error: The Leaf Certificate expiry value is invalid. It must be a number followed by 'y' (years), 'm' (months) or 'd' (days). e.g. 2y = 2 years, 24m = 2 years, 730d = 2 years. You provided: {options.LeafCertExpiry}");
            return false;
        }

        return true;
    }

    /// <summary>
    /// Parses command line arguments into a MinicaOptions object.
    /// Created by GitHub Copilot, extended by DaveG.
    /// </summary>
    /// <param name="args"></param>
    /// <returns></returns>
    private static MinicaOptions? ParseArgs(string[] args)
    {
        if (args.Length == 0) return null;

        var options = new MinicaOptions();

        // walk through args, left to right. When we find a known arg, we set the next one as the value.

        for (int argIndex = 0; argIndex < args.Length; argIndex++)
        {
#pragma warning disable S127 // "for" loop stop conditions should be invariant. Agree with SonarLint, but Copilot made me do it this way! :)
            switch (args[argIndex].ToLower())
            {
                case "--key-path":
                    if (argIndex + 1 < args.Length) options.KeyFilePath = args[++argIndex];
                    break;
                case "--cert-path":
                    if (argIndex + 1 < args.Length) options.CertFilePath = args[++argIndex];
                    break;
                case "--ca-filename":
                    if (argIndex + 1 < args.Length) options.CaFileName = args[++argIndex].Trim();
                    break;
                case "--ca-expiry":
                    if (argIndex + 1 < args.Length ) options.CaExpiry = args[++argIndex];
                    break;
                case "--intermediate-expiry":
                    if (argIndex + 1 < args.Length ) options.IntermediateCaExpiry = args[++argIndex];
                    break;
               case "--leaf-expiry":
                    if (argIndex + 1 < args.Length ) options.LeafCertExpiry = args[++argIndex];
                    break;
                case "--no-intermediate":
                    options.CreateIntermediateCA = false;
                    break;
                case "--ca-alg":
                    if (argIndex + 1 < args.Length) options.CaAlg = args[++argIndex];
                    break;
                case "--domains":
                    if (argIndex + 1 < args.Length) options.Domains = args[++argIndex];
                    break;
                case "--ip-addresses":
                    if (argIndex + 1 < args.Length) options.IpAddresses = args[++argIndex];
                    break;
                case "--ca-name":
                    if (argIndex + 1 < args.Length) options.RootCAName = args[++argIndex].Trim();
                    break;
                case "--user":
                    if (argIndex + 1 < args.Length) options.User = args[++argIndex];
                    break;
                case "--p12-password":
                    if (argIndex + 1 < args.Length) options.P12Password = args[++argIndex];
                    break;
                case "--organisation":
                    if (argIndex + 1 < args.Length) options.Organisation = args[++argIndex];
                    break;
                case "--organisational-unit":
                    if (argIndex + 1 < args.Length) options.OrganisationalUnit = args[++argIndex];
                    break;
                case "--country":
                    if (argIndex + 1 < args.Length) options.Country = args[++argIndex].ToUpper(); // must be upper case
                    break;
                case "--suffix-random":
                    options.SuffixRandomExtensionToCAName = true;
                    break;
                case "--add-client-eku-to-server-cert":
                    options.AddClientAuthEKUToServerCert = true;
                    break;
#pragma warning restore S127 // "for" loop stop conditions should be invariant
                case "--help":
                case "?":
                case "-h":
                    return null;
                default:
                    Log.Error($"Unknown argument: {args[argIndex]}");
                    return null;
            }
        }

        if (string.IsNullOrEmpty(options.Domains) && string.IsNullOrEmpty(options.IpAddresses) && string.IsNullOrEmpty(options.User))
            return null;

        return options;
    }

    /// <summary>
    /// Shows the usage instructions for the MiniCA application.
    /// </summary>
    static void ShowUsage()
    {
        // kept mostly to the original minica usage message https://github.com/jsha/minica/tree/master/.github/workflows
        // with a lot of additions/modifications...
        Log.Info(@"
MiniCA is a simple CA intended for use in situations where the CA operator
also operates each host where a certificate will be used. It automatically
generates both a key and a certificate when asked to produce a certificate.
It does not offer OCSP or CRL services. Minica is appropriate, for instance,
for generating certificates for RPC systems or microservices.

On first run, it will generate a keypair and a root certificate in the
current directory, and will reuse that same keypair and root certificate
unless they are deleted. This applies to intermediate CA certificates too.

On each run, it will generate a new keypair and sign an end-entity (leaf)
certificate for that keypair. The certificate will contain a list of DNS names
and/or IP addresses from the command line flags. The key and certificate are
placed in a new directory whose name is chosen as the first domain name from
the certificate, or the first IP address if no domain names are present. It
will not overwrite existing keys or certificates.

Usage:
  --ca-filename <file>            Root filename (default: minica)
  --key-path <path>               Path for all private keys (default: .\key\)
  --cert-path <path>              Path for all certificates (default: .\cert\)
  --ca-name <name>                Root CA name (default: Test)
  --ca-alg <algorithm>            Algorithm for any new keypairs: RSA or ECDSA (default: ecdsa)
  --ca-expiry <time>              Root CA validity period 99[y|m|d] (default: 20y) e.g. 240m = 20 years
  --intermediate-expiry <time>    Intermediate CA validity period 10[y|m|d] (default: 10y) e.g. 3650d = 10 years
  --leaf-expiry <time>            Leaf certificate validity period 2[y|m|d] (default: 2y) e.g. 6m = 6 months
  --no-intermediate               Do not create an intermediate CA, sign leaf certs directly from the root CA (not recommended)
  --domains <domains>             Comma separated domain names to include as Server Alternative Names
  --ip-addresses <ips>            Comma separated IP addresses to include as Server Alternative Names
  --user <upn>                    User Principal Name (UPN) to include for client certificates
  --p12-password <pwd>            Password for user P12 certificate file (default: letmein)
  --organisation <org>            Organisation to include in the certificate (default: none)
  --organisational-unit <ou>      Organisation Unit to include in the certificate (default: none)
  --suffix-random                 Suffix a random string to the CA name to avoid name collisions
  --country <cc>                  Country to include in the certificate (2 letter ISO 3166-1 alpha-2 code, default: none)
  --add-client-eku-to-server-cert Add the Client Authentication EKU to server certificates (some clients need this)
  -h, --help                      Show this help message

Examples:
  minica --ca-name ""My Company"" --domains localhost,example.com
  minica --ip-addresses 127.0.0.1,192.168.1.100
  minica --domains *.example.com --ca-alg rsa
  minica --user user@example.com
  minica --user dave@example.io --ca-name ""Example Root CA"" --organisation ""example.io"" --p12-password ""superS3curePazw0rd"" --organisational-unit ""Example User""
  minica --ca-name ""Example Root CA"" --domains www.example.com,localhost --ip-addresses 127.0.0.1,0.0.0.0 --organisation ""Example""            
");
    }
}