using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace MiniCA;

/// <summary>
/// Options for the Minica CA tool. Populated when we parse the command-line arguments.
/// </summary>
internal partial class MinicaOptions
{
    // adjust these if you want to change/relax the validation rules

    #region REGULAR EXPRESSIONS USED FOR VALIDATION
    /// <summary>
    /// Used to validate CA name (letters, digits, spaces, dots, hyphens, underscores).
    /// </summary>
    /// <returns></returns>
    [GeneratedRegex(@"^[A-Za-z0-9.\-_ ]+$")]
    private static partial Regex _ValidCANameRegEx();

    /// <summary>
    /// Used to validate organisation (letters, digits, spaces, and some punctuation).
    /// </summary>
    /// <returns></returns>
    [GeneratedRegex(@"^[A-Za-z0-9 .,'\-&()]+$")]
    private static partial Regex _ValidOrgRegEx();

    /// <summary>
    /// Used to validate organisational unit (letters, digits, spaces, dots, hyphens, underscores).
    /// </summary>
    /// <returns></returns>
    [GeneratedRegex(@"^[A-Za-z0-9 .,'\-&()]+$")]
    private static partial Regex OrganisationalUnitRegex();

    /// <summary>
    /// Used to validate DNS names (optionally with a leading wildcard).
    /// Rules:
    /// - Optional leading "*." to allow wildcard certificates (e.g., *.example.com)
    /// - Requires at least one dot (i.e. two or more labels)
    /// - Each non-wildcard label: alphanumeric, may contain hyphens but not start/end with one, length 1–63
    /// - Final label (TLD): letters only, length 2–63
    /// - Overall pattern rejects invalid characters and consecutive dots
    /// NOTE: Underscores are intentionally not allowed (they are not valid in hostnames, only in certain DNS record types).
    /// </summary>
    [GeneratedRegex(@"^(?:\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex _ValidDomainNameRegEx();


    /// <summary>
    /// Used to validate country (exactly 2 letters).
    /// </summary>
    /// <returns></returns>
    [GeneratedRegex(@"^[A-Za-z]{2}$")]
    private static partial Regex _ValidCountryRegEx();

    // ------------------------------------------------------------
    // User / UPN Validation
    // ------------------------------------------------------------
    // We accept either:
    // 1. Plain user identifier (sAMAccountName style): letters/digits plus . _ - (no leading/trailing separator, <=64 chars)
    // 2. UPN / email-like: local-part@domain
    //    - Local part: RFC 5322 simplified (atoms separated by single dots, allowed specials)
    //    - Domain: one or more DNS labels (enforces at least one dot)
    // 3. Active Directory single-label UPN realm (not recommended but possible): local-part@SINGLELABEL
    // NOTE: This remains a pragmatic validation, not a full RFC 5322 implementation.

    /// <summary>
    /// Regex for validating an Active Directory single-label UPN realm (e.g., user@ADDOMAIN).
    /// </summary>
    /// <returns></returns>
    [GeneratedRegex(@"^(?<local>[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*)@(?<realm>[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)$", RegexOptions.IgnoreCase | RegexOptions.Compiled, "en-GB")]
    private static partial Regex _UpnSingleLabelRealmRegex();

    /// <summary>
    /// Creates a compiled regular expression to validate plain user IDs.
    /// </summary>
    /// <remarks>The regular expression ensures that the user ID starts and ends with an alphanumeric
    /// character, and may contain alphanumeric characters, periods (.), underscores (_), or hyphens (-) in between. The
    /// total length must not exceed 64 characters.</remarks>
    /// <returns>A <see cref="Regex"/> instance configured to validate plain user IDs based on the specified pattern.</returns>

    [GeneratedRegex(@"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$", RegexOptions.Compiled)]
    private static partial Regex _PlainUserIdRegex();

    /// <summary>
    /// Creates a compiled regular expression to validate UPNs or email addresses with multi-label DNS domains.
    /// </summary>
    /// <remarks>The regular expression captures the local part and domain of the UPN/email address.</remarks>
    [GeneratedRegex(@"^(?<local>[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*)@(?<domain>(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})$", RegexOptions.IgnoreCase | RegexOptions.Compiled, "en-GB")]
    private static partial Regex _UpnDnsDomainRegex();

    /// <summary>
    /// Regex for validating plain user IDs (sAMAccountName style).
    /// </summary>
    private static readonly Regex PlainUserIdRegex = _PlainUserIdRegex();

    /// <summary>
    /// Standard UPN / email with multi-label DNS domain (requires at least one dot)
    /// </summary>
    private static readonly Regex UpnDnsDomainRegex = _UpnDnsDomainRegex();

    /// <summary>
    /// AD single-label UPN suffix (e.g., user@ADDOMAIN) – no dot in the realm
    /// </summary>
    private static readonly Regex UpnSingleLabelRealmRegex = _UpnSingleLabelRealmRegex();
    #endregion

    #region PROPERTIES SET FROM COMMAND LINE    
    /// <summary>
    /// The actual name of the root CA to create, it adds " Root CA" automatically. e.g. "My Company" -> "My Company Root CA"
    /// </summary>
    internal string RootCAName { get; set; } = "Test"; // e.g "Test" -> "Test Root CA" | -> "Test Root CA 1234" if SuffixRandomExtensionToCAName is true

    /// <summary>
    /// Filename (without path or extension) for the CA files (root or intermediate).
    /// e.g. "rootca" -> rootca.crt and rootca.key | rootca-intermediate.crt and rootca-intermediate.key
    /// </summary>
    internal string CaFileName { get; set; } = "minica"; /// i.e. combined to make minica.crt and minica.key (without path)

    /// <summary>
    /// The file path for private keys.
    /// </summary>
    internal string KeyFilePath { get; set; } = @".\key";

    /// <summary>
    /// The file path for certificate.
    /// </summary>
    internal string CertFilePath { get; set; } = @".\cert";

    /// <summary>
    /// The algorithm to use for the CA key.
    /// Default is "ecdsa" for nistP384, or "rsa" for RSA 2048-bit.
    /// 
    /// Generally, ECDSA is preferred for better security and performance, unless compatibility with older systems is required.
    /// </summary>
    public string CaAlg { get; set; } = "ecdsa"; // or "rsa"

    /// <summary>
    /// Domains to include in the certificate.
    /// </summary>
    public string Domains { get; set; } = string.Empty;

    /// <summary>
    /// IP addresses to include in the certificate.
    /// </summary>
    public string IpAddresses { get; set; } = string.Empty;

    /// <summary>
    /// User Principal Name (UPN) for a client certificate.
    /// </summary>
    public string User { get; set; } = string.Empty;

    /// <summary>
    /// Returns true if a client certificate should be created (i.e., if the User property is not empty).
    /// </summary>
    public bool IsClientCert
    {
        get
        {
            return !string.IsNullOrEmpty(User); // if User is not empty, we are creating a client cert, otherwise a server cert...
        }
    }

    /// <summary>
    /// Password for the P12 client certificate file. Please use a strong password, not the default one.
    /// </summary>
    public string P12Password { get; set; } = "letmein";

    /// <summary>
    /// The organisation to include in the certificate.
    /// </summary>
    public string Organisation { get; set; } = ""; // spelling correct for _English_

    /// <summary>
    /// Organisational Unit to include in the certificate.
    /// </summary>
    public string OrganisationalUnit { get; set; } = ""; // spelling correct for _English_

    /// <summary>
    /// The country to include in the certificate.
    /// </summary>
    public string Country { get; set; } = "";

    /// <summary>
    /// "My Root CA" vs "My Root CA 1234" to avoid name collisions.
    /// 
    /// false - keep the CA name the same for each run (better).
    /// true - suffix it with a random string to avoid name collisions.
    /// </summary>
    public bool SuffixRandomExtensionToCAName { get; set; } = false;

    /// <summary>
    /// Allows the user to include the Client Authentication EKU in server certificates.
    /// </summary>
    public bool AddClientAuthEKUToServerCert { get; set; } = false;

    /// <summary>
    /// Create an intermediate CA, and issue leaf certificates from it if true.
    /// Best practice is to use an intermediate CA.
    /// </summary>
    public bool CreateIntermediateCA { get; set; } = true;

    /// <summary>
    /// How long the certificates are valid for.
    /// </summary>
    public string CaExpiry { get; set; } = "20y"; // default 20 years

    /// <summary>
    /// How long the intermediate CA certificates are valid for.
    /// </summary>
    public string IntermediateCaExpiry { get; set; } = "10y"; // default 10 years

    /// <summary>
    /// How long the leaf certificate are valid for.
    /// </summary>
    public string LeafCertExpiry { get; set; } = "2y"; // default 2 years
    #endregion
    
    #region METHODS TO CONVERT EXPIRY STRINGS TO TIMESPAN
    /// <summary>
    /// Converts a certificate expiry string (e.g., "20y", "10m", "5d") to a TimeSpan.
    /// </summary>
    /// <param name="expiryString">The expiry string to convert.</param>
    /// <returns>The corresponding TimeSpan.</returns>
    public static TimeSpan ConvertExpiryStringToTimeSpan(string expiryString)
    {
        if (string.IsNullOrEmpty(expiryString))
        {
            throw new ArgumentException("Invalid expiry string.", nameof(expiryString));
        }

        char unit = expiryString[^1];
        if (!int.TryParse(expiryString[..^1], out int value))
        {
            throw new ArgumentException("Invalid expiry string.", nameof(expiryString));
        }

        return unit switch
        {
            'y' => TimeSpan.FromDays(365 * value),
            'm' => TimeSpan.FromDays(30 * value),
            'd' => TimeSpan.FromDays(value),
            _ => throw new ArgumentException("Invalid expiry string.", nameof(expiryString)),
        };
    }

    /// <summary>
    /// Returns true if the expiry string is valid (e.g., "20y", "10m", "5d").
    /// </summary>
    /// <param name="expiryString"></param>
    /// <returns></returns>
    public static bool IsValidExpiryString(string expiryString)
    {
        if (string.IsNullOrEmpty(expiryString) || expiryString.Length < 2) return false;
        
        char unit = expiryString[^1];
        
        if (!int.TryParse(expiryString[..^1], out int value)) return false;
        
        return unit == 'y' || unit == 'm' || unit == 'd';
    }
    #endregion

    #region METHODS TO GET FILE PATHS AND NAMES
    /// <summary>
    /// Static random suffix used to make CA names unique if SuffixRandomExtensionToCAName is true.
    /// </summary>
    private readonly string _randomHexSuffix = GenerateRandomHex(3);

    /// <summary>
    /// Returns the full distinguished name for the root CA, including " Root CA" and an optional random suffix.
    /// </summary>
    internal string FullCAName
    {
        get
        {
            string randomSuffix = SuffixRandomExtensionToCAName ? $" {_randomHexSuffix}" : "";

            // create the distinguished name for the root CA, including a random suffix if requested
            string name = RootCAName + " Root CA" + randomSuffix;

            return name;
        }
    }

    /// <summary>
    /// Returns the full distinguished name for the intermediate CA, including " Intermediate CA" and an optional random suffix.
    /// </summary>
    internal string FullIntermediateCAName
    {
        get
        {
            string randomSuffix = SuffixRandomExtensionToCAName ? $" {_randomHexSuffix}" : "";

            // create the distinguished name for the intermediate CA, including a random suffix if requested
            string name = RootCAName + " Intermediate CA" + randomSuffix;
            return name;
        }
    }

    /// <summary>
    /// Generates a random hexadecimal string of the specified byte length, used to make CA name suffix.
    /// </summary>
    /// <param name="bytes"></param>
    /// <returns></returns>
    private static string GenerateRandomHex(int bytes)
    {
        byte[] random = new byte[bytes];

        using RandomNumberGenerator rng = RandomNumberGenerator.Create();

        rng.GetBytes(random);

        return Convert.ToHexString(random).ToLower();
    }

    /// <summary>
    /// Returns the full file path for the root CA certificate file (e.g., "C:\path\to\certs\minica.crt").
    /// </summary>
    internal string RootCACertFilePath
    {
        get
        {
            return Path.Combine(CertFilePath, CaFileName + ".crt");
        }
    }

    /// <summary>
    /// Returns true if the root CA certificate file exists.
    /// </summary>
    /// <returns></returns>
    internal bool RootCACertFileExists
    {
        get
        {
            return File.Exists(RootCACertFilePath);
        }
    }

    /// <summary>
    /// Returns the full file path for the root CA key file (e.g., "C:\path\to\keys\minica.key").
    /// </summary>
    internal string RootCAKeyFilePath
    {
        get
        {
            return Path.Combine(KeyFilePath, CaFileName + ".key");
        }
    }

    /// <summary>
    /// Returns true if the root CA key file exists.
    /// </summary>
    /// <returns></returns>
    internal bool RootCAKeyFileExists
    {
        get
        {
            return File.Exists(RootCAKeyFilePath);
        }
    }

    /// <summary>
    /// Returns the full file path for the intermediate CA certificate file (e.g., "C:\path\to\certs\minica-intermediate.crt").
    /// </summary>
    internal string IntermediateCACertFilePath
    {
        get
        {
            return Path.Combine(CertFilePath, CaFileName + "-intermediate.crt");
        }
    }

    /// <summary>
    /// Returns true if the intermediate CA certificate file exists.
    /// </summary>
    /// <returns></returns>
    internal bool IntermediateCACertFileExists
    {
        get
        {
            return File.Exists(IntermediateCACertFilePath);
        }
    }

    /// <summary>
    /// Returns the full file path for the intermediate CA key file (e.g., "C:\path\to\keys\minica-intermediate.key").
    /// </summary>
    internal string IntermediateCAKeyFilePath
    {
        get
        {
            return Path.Combine(KeyFilePath, CaFileName + "-intermediate.key");
        }
    }

    /// <summary>
    /// Returns true if the intermediate CA key file exists.
    /// </summary>
    /// <returns></returns>
    internal bool IntermediateCAKeyFileExists
    {
        get
        {
            return File.Exists(IntermediateCAKeyFilePath);
        }
    }

    /// <summary>
    /// Returns the full file path for the leaf certificate file (e.g., "C:\path\to\certs\example.com.crt").
    /// </summary>
    internal string LeafCertFilePath
    {
        get
        {
            string domainOrIP = LeafNameAsUserIPorDomain();

            return Path.Combine(CertFilePath, domainOrIP + ".crt");
        }
    }

    /// <summary>
    /// Returns a suitable leaf name based on the User, Domains, or IpAddresses properties.
    /// </summary>
    /// <returns></returns>
    private string LeafNameAsUserIPorDomain()
    {
        string domainOrIP;

        if (IsClientCert)
        {
            domainOrIP = User;
        }
        else if (GetDomainsAsArray().Length > 0)
        {
            domainOrIP = GetDomainsAsArray()[0];
        }
        else if (GetIpAddressesAsArray().Length > 0)
        {
            domainOrIP = GetIpAddressesAsArray()[0];
        }
        else
        {
            domainOrIP = "default";
        }

        // Replace any '*' in wildcard domains with 'wildcard-' to make a valid filename
        if (domainOrIP.Contains('*'))
        {
            domainOrIP = domainOrIP.Replace("*.", "wildcard-");
        }

        return domainOrIP;
    }

    /// <summary>
    /// Returns the full file path for the leaf key file (e.g., "C:\path\to\keys\example.com.key").
    /// </summary>
    internal string LeafKeyFilePath
    {
        get
        {
            string domainOrIP = LeafNameAsUserIPorDomain();

            return Path.Combine(KeyFilePath, domainOrIP + ".key");
        }
    }

    /// <summary>
    /// Returns the full file path for the leaf full-chain certificate file (e.g., "C:\path\to\certs\example.com.fullchain.crt").
    /// </summary>
    internal string LeafFullChainCertFilePath
    {
        get
        {
            string domainOrIP = LeafNameAsUserIPorDomain();

            return Path.Combine(CertFilePath, domainOrIP + ".fullchain.crt");
        }
    }

    /// <summary>
    /// Returns the full file path for the leaf full-chain key file (e.g., "C:\path\to\keys\example.com.fullchain.key").
    /// </summary>
    internal string LeafFullChainKeyFilePath
    {
        get
        {
            string domainOrIP = LeafNameAsUserIPorDomain();

            return Path.Combine(KeyFilePath, domainOrIP + ".fullchain.key");
        }
    }

    /// <summary>
    /// Returns the full file path for the leaf P12 certificate file (e.g., "C:\path\to\certs\example.com.p12").
    /// </summary>
    internal string LeafP12FilePath
    {
        get
        {
            string domainOrIP = LeafNameAsUserIPorDomain();
            return Path.Combine(CertFilePath, domainOrIP + ".p12");
        }
    }
    #endregion

    #region VALIDATION METHODS
    /// <summary>
    /// Returns the domains as an array of trimmed strings.
    /// </summary>
    /// <returns></returns>
    internal string[] GetDomainsAsArray()
    {
        return SplitCommaSeparated(Domains);
    }

    /// <summary>
    /// Splits a comma-separated string into an array of trimmed strings.
    /// </summary>
    /// <param name="input"></param>
    /// <returns>Input string split into array of trimmed strings.</returns>
    private static string[] SplitCommaSeparated(string input)
    {
        if (string.IsNullOrEmpty(input)) return [];

        return [.. input.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim())];
    }

    /// <summary>
    /// Validates the domain names, returning false if any are malformed.
    /// </summary>
    /// <param name="domainErrorMessage">(out) The error message.</param>
    /// <returns>true - all domains are valid.</returns>
    internal bool AreDomainsValid(out string domainErrorMessage)
    {
        domainErrorMessage = "";

        Regex domainRegex = _ValidDomainNameRegEx();

        foreach (string domain in GetDomainsAsArray())
        {
            if (domain.Equals("localhost", StringComparison.CurrentCultureIgnoreCase)) continue; // it is valid to have localhost as a domain

            if (!domainRegex.IsMatch(domain))
            {
                domainErrorMessage = domain;
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Validates the IP addresses, returning false if any are malformed.
    /// </summary>
    /// <param name="ipAddressErrorMessage">(out) The error message.</param>
    /// <returns>true - all IP addresses are valid.</returns>
    internal bool AreIpAddressesValid(out string ipAddressErrorMessage)
    {
        ipAddressErrorMessage = "";

        foreach (var ip in GetIpAddressesAsArray())
        {
            if (!IPAddress.TryParse(ip, out _))
            {
                ipAddressErrorMessage = ip;
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Returns the IP addresses as an array of trimmed strings.
    /// </summary>
    /// <returns>An string[] of the IP addresses (rather than string).</returns>
    internal string[] GetIpAddressesAsArray()
    {
        return SplitCommaSeparated(IpAddresses);
    }

    /// <summary>
    /// Returns true if the User property is empty or a valid plain user id or UPN/email.
    /// </summary>
    internal bool IsValidUser()
    {
        if (string.IsNullOrWhiteSpace(User)) return true;

        // Trim just in case external input had spaces
        var candidate = User.Trim();

        // Order: cheap checks first
        if (PlainUserIdRegex.IsMatch(candidate)) return true;
        if (UpnDnsDomainRegex.IsMatch(candidate)) return true;
        if (UpnSingleLabelRealmRegex.IsMatch(candidate)) return true;

        return false;
    }

    /// <summary>
    /// Returns true if the CA key file-path is valid (i.e., has a .key extension).
    /// </summary>
    /// <returns></returns>
    internal bool IsValidKeyFilePath()
    {
        return Directory.Exists(KeyFilePath);
    }

    /// <summary>
    /// Returns true if the CA certificate file-path is valid (i.e., has a .crt extension).
    /// </summary>
    /// <returns></returns>
    internal bool IsValidCertFilePath()
    {
        return Directory.Exists(CertFilePath);
    }

    /// <summary>
    /// Returns true if the organisation is either empty or does not contain special characters.
    /// </summary>
    /// <returns></returns>
    internal bool IsValidOrganisation()
    {
        // Organisation can be empty, but if not, it must not contain special characters
        if (string.IsNullOrEmpty(Organisation)) return true;

        if (Organisation.Length > 64) return false;

        Regex orgRegex = _ValidOrgRegEx();

        return orgRegex.IsMatch(Organisation);
    }

    /// <summary>
    /// Returns true if the organisation unit is either empty or does not contain special characters.
    /// </summary>
    /// <returns></returns>
    internal bool IsValidOrganisationalUnit()
    {
        // Organisation Unit can be empty, but if not, it must not contain special characters
        if (string.IsNullOrEmpty(OrganisationalUnit)) return true;

        if (OrganisationalUnit.Length > 64) return false;

        Regex orgUnitRegex = OrganisationalUnitRegex();

        return orgUnitRegex.IsMatch(OrganisationalUnit);
    }

    /// <summary>
    /// Returns true if the country is either empty or exactly 2 letters.
    /// </summary>
    /// <returns></returns>
    internal bool IsValidCountry()
    {
        // Country can be empty, but if not, it must be exactly 2 letters
        if (string.IsNullOrEmpty(Country)) return true;

        if (Country.Length != 2) return false;

        Regex countryRegex = _ValidCountryRegEx();

        return countryRegex.IsMatch(Country);
    }

    /// <summary>
    /// Returns true if the algorithm is supported: i.e. either "ecdsa" or "rsa" (case insensitive).
    /// </summary>
    /// <returns></returns>
    internal bool IsValidAlgorithm()
    {
        string alg = CaAlg.ToLower();

        return alg == "ecdsa" || alg == "rsa";
    }

    /// <summary>
    /// Validates the root CA name, returning false if it is empty, too long, or contains invalid characters.
    /// </summary>
    /// <param name="invalidCAErrorMessage">(out) the error messsage.</param>
    /// <returns>true if the CA Name is valid.</returns>
    internal bool IsValidCAName(out string invalidCAErrorMessage)
    {
        invalidCAErrorMessage = "";

        // we are appending " Root CA" to the name, so remove it if the user included it...
        if (RootCAName.Contains("root", StringComparison.InvariantCultureIgnoreCase))
        {
            // remove " root ca" from the name if the user included it...
            RootCAName = RootCAName.Replace(" root ca", "", StringComparison.InvariantCultureIgnoreCase).Trim();
        }

        if (string.IsNullOrEmpty(RootCAName))
        {
            invalidCAErrorMessage = "Error: CA name cannot be empty.";
            return false;
        }

        // there is a maximum length for the root CA name, which is typically 64 characters, less for non Latin characters.
        if (RootCAName.Length > 64 - " Root CA".Length - (SuffixRandomExtensionToCAName ? 34 : 0))
        {
            invalidCAErrorMessage = "Root CA name cannot exceed 64 characters (including \" Root CA\" " + (SuffixRandomExtensionToCAName ? " and 3 digit random " : "") + " suffix";
            return false;
        }

        // Generally, root CA names can contain alphanumeric characters (letters and numbers), hyphens (-), and underscores (_).
        // Some systems may also allow periods (.), but this can depend on the specific implementation and whether interoperability with other systems is a concern. 
        Regex caNameRegex = _ValidCANameRegEx();

        // Ensure the root CA name is valid
        if (!caNameRegex.IsMatch(RootCAName))
        {
            invalidCAErrorMessage = $"Invalid root CA name: {RootCAName}";
            return false;
        }

        return true;
    }

    /// <summary>
    /// Validates the CA file name, returning false if it is empty, too long, or contains invalid characters.
    /// </summary>
    /// <returns></returns>
    /// <exception cref="NotImplementedException"></exception>
    internal bool IsValidCaFileName(out string invalidCAErrorMessage)
    {
        invalidCAErrorMessage = "";

        // CaFileName cannot be empty, too long, or contain invalid characters. It must be a valid file name without path or extension.

        if (string.IsNullOrEmpty(CaFileName))
        {
            invalidCAErrorMessage = "Error: CA file name cannot be empty.";
            return false;
        }

        string filepath = IntermediateCACertFilePath; // just to get the full path for validation

        if (Path.GetInvalidPathChars().Any(c => filepath.Contains(c)) || Path.GetInvalidFileNameChars().Any(c => CaFileName.Contains(c)))
        {
            invalidCAErrorMessage = $"Error: CA file name contains invalid characters: {CaFileName}";
            return false;
        }

        if (filepath.Length > 255)
        {
            invalidCAErrorMessage = $"Error: CA file path will be too long (max 255 characters): {filepath}";
            return false; // typical max path length on many file systems
        }

        return true;
    }
    #endregion
}