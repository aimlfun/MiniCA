using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace MiniCA;

// This is an extended C# port of the MiniCA tool (https://github.com/jsha/minica), using GitHub Copilot with a few manual "tweaks".
// Original code is written in Go and licensed under the MIT License.
// MIT License applies to the original code.

// No further claims are made by the existence of this port.

/// <summary>
/// A C# port of the MiniCA tool on steroids! Want to understand more about semantics and standards of certificates? https://www.rfc-editor.org/rfc/rfc5280
/// </summary>
internal static class MiniCATool
{
    #region CONSTANTS

    // EKU OIDs
    /// <summary>
    /// Allows CA to validate client certificates i.e. for user authentication (mutual TLS).
    /// (Client Authentication) identifies a certificate's purpose to authenticate a client. 
    /// </summary>
    private const string EKU_CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2";

    /// <summary>
    /// Allows CA to validate server certificates i.e. for web servers.
    /// (Server Authentication) identifies a certificate's purpose to authenticate a server.
    /// </summary>
    private const string EKU_SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1";
    #endregion

    /// <summary>
    /// Indicates it generated a root certificate.
    /// </summary>
    private static bool _generatedRootCA = false;

    /// <summary>
    /// Indicates it generated an intermediate CA certificate.
    /// </summary>
    private static bool _generatedIntermediateCA = false;

    /// <summary>
    /// Indicates it generated a leaf certificate.
    /// </summary>
    private static bool _generatedLeafCert = false;

    /// <summary>
    /// Indicates if verification of the generated certificate failed.
    /// By verification we mean after we've created the cert, we try to validate it in a
    /// number of ways, and one of them spotted an error. We use the flag for any automation
    /// to know - it goes in the .json.
    /// </summary>
    private static bool _failedVerification = false;

    /// <summary>
    /// Used to format JSON output with indentation for better readability.
    /// </summary>
    private static readonly JsonSerializerOptions IndentedJsonOptions = new() { WriteIndented = true };

    /// <summary>
    /// Runs the MiniCA logic with the specified options.
    /// EXPECTS VALID INPUTS: Program.cs does that validation, we don't repeat it here.
    /// </summary>
    /// <param name="options"></param>
    /// <exception cref="ArgumentException"></exception>
    internal static void CreateSpecifiedCertificate(MinicaOptions options)
    {
        // Parse algorithm
        CertificateAlgorithm algorithm = CertificateAlgorithm.ECDSA;

        if (options.CaAlg.Equals("rsa", StringComparison.OrdinalIgnoreCase))
        {
            algorithm = CertificateAlgorithm.RSA;
        }
        else if (!options.CaAlg.Equals("ecdsa", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException($"Unrecognized algorithm: {options.CaAlg} (use RSA or ECDSA)");
        }

        // get or create issuer (it creates if none exists)
        Issuer issuer = GetIssuerCreatingIfMissing(algorithm, options);

        // these are the domains and IP addresses to be included in the certificate, already validated

        // sign the certificate
        SignCertificate(issuer, options.GetDomainsAsArray(), options.GetIpAddressesAsArray(), algorithm, options);
    }

    /// <summary>
    /// Gets the issuer certificate and private key from the specified files.
    /// </summary>
    /// <param name="algorithm">What algorithm to use.</param>
    /// <param name="options">User specified options.</param>
    /// <returns></returns>
    /// <exception cref="FileNotFoundException"></exception>
    private static Issuer GetIssuerCreatingIfMissing(CertificateAlgorithm algorithm, MinicaOptions options)
    {
        bool keyFileExists = options.RootCAKeyFileExists;
        bool certFileExists = options.RootCACertFileExists;

        // neither the key or cert file exists for the CA signing cert, so we need to create the Issuer (CA)
        if (!keyFileExists && !certFileExists)
        {
            MakeIssuer(algorithm, options);
            _generatedRootCA = true; // flag that we generated a new root CA, so we can put it into the JSON

            return GetIssuerCreatingIfMissing(algorithm, options);
        }
        else
        {
            if (!_generatedRootCA)
            {
                Log.Info($"Root CA certificate:");
                Log.Info(" - " + Path.GetFullPath(options.RootCACertFilePath));
                Log.Info(" - " + Path.GetFullPath(options.RootCAKeyFilePath));
                Log.Info(""); // spacer
            }
        }

        // one of the files is missing, so we cannot proceed
        if (!keyFileExists && certFileExists)
            throw new FileNotFoundException($"{options.RootCAKeyFilePath} (but {options.RootCACertFilePath} exists)");

        if (keyFileExists && !certFileExists)
            throw new FileNotFoundException($"{options.RootCACertFilePath} (but {options.RootCAKeyFilePath} exists)");

        // intermediate CA paths are based on the root CA paths, e.g. minica-intermediate.crt and minica-intermediate.key
        string intermediateCertPath = options.IntermediateCACertFilePath;
        string intermediateKeyPath = options.IntermediateCAKeyFilePath;

        string issuerCertPath;
        string issuerKeyPath;

        // if both intermediate files exist, use them - and sign with the intermediate CA. If only one (or none) exists, ignore it and use the root CA.
        if (File.Exists(intermediateCertPath) && File.Exists(intermediateKeyPath))
        {
            issuerCertPath = intermediateCertPath;
            issuerKeyPath = intermediateKeyPath;

            if (!_generatedIntermediateCA)
            {
                Log.Info($"Intermediate CA certificate:");
                Log.Info(" - " + Path.GetFullPath(intermediateCertPath));
                Log.Info(" - " + Path.GetFullPath(intermediateKeyPath));
                Log.Info(""); // spacer
            }

            SigningWith("Intermediate CA");
        }
        else
        {
            issuerCertPath = options.RootCACertFilePath;
            issuerKeyPath = options.RootCAKeyFilePath;

            if (options.CreateIntermediateCA) // unless explicitly asked to not create an intermediate CA, we warn if none is found.
            {
                Log.Warn("No intermediate CA certificate was found.");
            }

            SigningWith("Root CA");
        }

        // read the existing key (CA or non)
        X509Certificate2 certWithKey = GetCACertificate(signingCertificateFilePath: issuerCertPath, signingCertificateKeyFilePath: issuerKeyPath, signingCertificate: out X509Certificate2 _, signingCertificateKey: out AsymmetricAlgorithm key);

        return new Issuer { Key = key, Certificate = certWithKey, CertificateFilePath = Path.GetFullPath(issuerCertPath), CertificateKeyFilePath = Path.GetFullPath(issuerKeyPath) };
    }

    /// <summary>
    /// Outputs to the console which certificate is being used for signing.
    /// 
    /// Signing with the [ Intermediate CA ] certificate
    /// </summary>
    /// <param name="text"></param>
    private static void SigningWith(string text)
    {
        Log.Info("Signing with the ", false);
        Console.BackgroundColor = ConsoleColor.Red;
        Console.ForegroundColor = ConsoleColor.Black;
        Log.Info($" {text} ", false);
        Console.ResetColor();
        Log.Info(" certificate");
    }

    /// <summary>
    /// Gets the CA / Intermediate certificate from file.
    /// </summary>
    /// <param name="signingCertificateFilePath"></param>
    /// <param name="signingCertificateKeyFilePath"></param>
    /// <param name="signingCertificate"></param>
    /// <param name="signingCertificateKey"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"></exception>
    private static X509Certificate2 GetCACertificate(string signingCertificateFilePath, string? signingCertificateKeyFilePath, out X509Certificate2 signingCertificate, out AsymmetricAlgorithm signingCertificateKey)
    {
        signingCertificateKeyFilePath ??= Path.ChangeExtension(signingCertificateFilePath, ".key");

        string certContents = File.ReadAllText(signingCertificateFilePath); //  read the certificate
        string keyContents = File.ReadAllText(signingCertificateKeyFilePath); // read the private key

        // convert them to usable key and cert objects

        signingCertificate = ReadCertificate(certContents);
        signingCertificateKey = ReadPrivateKey(keyContents);

        // combine them into a single object with both cert and key -> X509Certificate2 
        X509Certificate2 certWithKey = signingCertificateKey switch
        {
            RSA rsa => signingCertificate.CopyWithPrivateKey(rsa),
            ECDsa ecd => signingCertificate.CopyWithPrivateKey(ecd),
            _ => throw new ArgumentException("Unsupported key type")
        };

        return certWithKey;
    }

    /// <summary>
    /// Makes a new issuer (CA) certificate and private key.
    /// </summary>
    /// <param name="certificateAlgorithm"></param>
    /// <param name="options"></param>
    private static void MakeIssuer(CertificateAlgorithm certificateAlgorithm, MinicaOptions options)
    {
        AsymmetricAlgorithm key = MakeKey(options.RootCAKeyFilePath, certificateAlgorithm);

        MakeRootCert(key, options, certificateAlgorithm);
    }

    /// <summary>
    /// Makes a new private key and saves it to the specified file.
    /// </summary>
    /// <param name="privateKeyFilePath"></param>
    /// <param name="algorithm"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"></exception>
    private static AsymmetricAlgorithm MakeKey(string privateKeyFilePath, CertificateAlgorithm algorithm)
    {
        AsymmetricAlgorithm key = algorithm switch
        {
            CertificateAlgorithm.RSA => RSA.Create(2048),
            CertificateAlgorithm.ECDSA => ECDsa.Create(ECCurve.NamedCurves.nistP384),
            _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}"),
        };

        var pemKey = ExportPrivateKeyToPem(key);

        WriteAndApplyFilePermissions(privateKeyFilePath, pemKey);

        return key;
    }

    /// <summary>
    /// Exports the private key to PEM format.
    /// </summary>
    /// <param name="algorithm"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"></exception>
    private static string ExportPrivateKeyToPem(AsymmetricAlgorithm algorithm)
    {
        byte[] keyBytes;

        if (algorithm is RSA rsa)
        {
            keyBytes = rsa.ExportPkcs8PrivateKey();
        }
        else if (algorithm is ECDsa ecdsa)
        {
            keyBytes = ecdsa.ExportPkcs8PrivateKey();
        }
        else
        {
            throw new ArgumentException("Unsupported key type");
        }

        return "-----BEGIN PRIVATE KEY-----\n" +
              $"{Convert.ToBase64String(keyBytes, Base64FormattingOptions.InsertLineBreaks)}\n" +
              "-----END PRIVATE KEY-----\n";
    }

    /// <summary>
    /// Makes the root CA certificate and saves it to the specified file.
    /// </summary>
    /// <param name="asymmetricAlgorithm"></param>
    /// <param name="options"></param>
    /// <exception cref="ArgumentException"></exception>
    private static void MakeRootCert(AsymmetricAlgorithm asymmetricAlgorithm, MinicaOptions options, CertificateAlgorithm certificateAlgorithm)
    {
        string name = options.FullCAName; // create the distinguished name for the root CA, including a random suffix if requested

        string distinguishedNameString = GetDistinguishedName(options, name, isLeaf: false);

        // this is the root CA certificate.
        X500DistinguishedName distinguishedName = new(distinguishedNameString, X500DistinguishedNameFlags.UseUTF8Encoding);

        CertificateRequest request;

        if (asymmetricAlgorithm is RSA rsa)
        {
            request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        else if (asymmetricAlgorithm is ECDsa ecdsa)
        {
            request = new CertificateRequest(distinguishedName, ecdsa, HashAlgorithmName.SHA256);
        }
        else
        {
            throw new ArgumentException("Unsupported key type");
        }

        // without an intermediate CA, the root CA is used to authenticate server / clients.
        if (!options.CreateIntermediateCA)
        {
            // they can also be used to authenticate server / clients.
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                enhancedKeyUsages: [
                    new Oid(EKU_SERVER_AUTH_OID), // serverAuth - allows root CA to validate server certificates i.e. for web servers
                new Oid(EKU_CLIENT_AUTH_OID)  // clientAuth - allows root CA to validate client certificates i.e. for user authentication (mutual TLS)
                ],
                critical: false));
        }

        // allow exactly one subordinate CA (the intermediate).
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: true,
                hasPathLengthConstraint: true,
                pathLengthConstraint: 1, // <- exactly one intermediate.
                critical: true));

        // key usage unchanged (root only signs certs / CRLs)
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                keyUsages: X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                critical: true));

        // Extended Key Usage:
        // With an intermediate present we OMIT EKU on the root (unconstrained).  This is important
        // from a security perspective. A root CA should only be responsible for signing and revoking
        // certificates. It has no role in authenticating servers or clients.

        // Add subject key identifier
        byte[] skid = CalculateSubjectKeyIdentifier(asymmetricAlgorithm);

        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(skid, false));

        // self-sign the root CA certificate, and make it valid for chosen number of years/months/days
        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.Add(MinicaOptions.ConvertExpiryStringToTimeSpan(options.CaExpiry)));

        // write the root CA certificate in PEM, CRT format, and KEY format
        // **THIS DOES NOT OVERWRITE. IF YOU WANT A CA REGEN, DELETE THE FILES FIRST.**

        string pemCert = ExportCertificateToPem(certificate);

        // write the root CA certificate and key in PEM format => minica.crt | minica.key
        WriteAndApplyFilePermissions(options.RootCACertFilePath, pemCert); // ,crt
        WriteAndApplyFilePermissions(options.RootCAKeyFilePath, ExportPrivateKeyToPem(asymmetricAlgorithm)); // .key

        string serial = certificate.GetSerialNumberString().ToLower();
        LogCACertificateFilePathToConsole("Root CA", Path.GetFullPath(options.RootCACertFilePath), Path.GetFullPath(options.RootCAKeyFilePath), serial);

        string intermediateCertName = options.FullIntermediateCAName; // create the intermediate CA name, same as root but with "Intermediate" in the name

        if (options.CreateIntermediateCA)
        {
            // Create an intermediate CA signed by the root CA
            // Convention: If the root is "xxxx Root CA" then the intermediate is "xxxx Intermediate CA"
            CreateIntermediateCa(
                options,
                certificate,
                intermediateCertName,
                certificateAlgorithm);
        }
    }

    /// <summary>
    /// Outputs the file paths of the generated Root CA certificate and private key to the console.
    /// Generated  Root CA  certificate:
    /// -  SERIAL #    1234567890abcdef
    /// -  CERTIFICATE  C:\..\MiniCA\bin\Debug\net9.0\minica.crt
    /// -  PRIVATE KEY  C:\..\MiniCA\bin\Debug\net9.0\minica.key
    /// </summary>
    /// <param name="CACertFilePath"></param>
    /// <param name="CAKeyFilePath"></param>
    /// <param name="certificateSerialNumber"></param>
    private static void LogCACertificateFilePathToConsole(string label, string CACertFilePath, string CAKeyFilePath, string certificateSerialNumber)
    {
        Log.Info("Generated ", false);
        Console.BackgroundColor = ConsoleColor.Red;
        Console.ForegroundColor = ConsoleColor.Black;
        Log.Info($" {label} ", false);
        Console.ResetColor();
        Log.Info(" certificate:");

        LogBlueBullet("SERIAL #", certificateSerialNumber);
        LogBlueBullet("CERTIFICATE", CACertFilePath);
        LogBlueBullet("PRIVATE KEY", CAKeyFilePath);

        Log.Info(""); // spacer
    }

    /// <summary>
    /// Outputs a blue bullet point with a message and value to the console.
    /// </summary>
    /// <param name="message"></param>
    /// <param name="value"></param>
    private static void LogBlueBullet(string message, string value)
    {
        Log.Info(" - ", false);
        Console.BackgroundColor = ConsoleColor.Blue;
        Log.Info($" {message,-12} ", false);
        Console.ResetColor();
        Log.Info(" " + value);
    }

    /// <summary>
    /// Creates an intermediate CA certificate signed by the given root CA.
    /// </summary>
    /// <param name="rootCert"></param>
    /// <param name="commonName"></param>
    /// <param name="algorithm">Default for the intermediate CA certificate algorithm is ECDSA.</param>
    /// <returns></returns>
    private static void CreateIntermediateCa(
        MinicaOptions options,
        X509Certificate2 rootCert,
        string commonName,
        CertificateAlgorithm algorithm = CertificateAlgorithm.ECDSA)
    {
        bool keyFileExists = options.IntermediateCAKeyFileExists;
        bool certFileExists = options.IntermediateCACertFileExists;

        // return the intermediate certificate
        if (certFileExists && keyFileExists)
        {
            Log.Info("Intermediate CA certificate and key already exist, skipping creation.");
            return; // don't recreate it !
        }

        // one of the files is missing, so we cannot proceed
        if (!keyFileExists && certFileExists)
            throw new FileNotFoundException($"{options.IntermediateCAKeyFileExists} (but {options.IntermediateCACertFilePath} exists)");

        if (keyFileExists && !certFileExists)
            throw new FileNotFoundException($"{options.IntermediateCACertFilePath} (but {options.IntermediateCAKeyFileExists} exists)");

        _generatedIntermediateCA = true; // flag that we generated a new intermediate CA, so we can put it into the JSON

        AsymmetricAlgorithm interKey = algorithm switch
        {
            CertificateAlgorithm.RSA => RSA.Create(2048),
            CertificateAlgorithm.ECDSA => ECDsa.Create(ECCurve.NamedCurves.nistP384),
            _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}"),
        };

        string distinguishedNameString = GetDistinguishedName(options, commonName, isLeaf: false);

        var dn = new X500DistinguishedName(distinguishedNameString, X500DistinguishedNameFlags.UseUTF8Encoding);

        // IMPORTANT: Use the intermediate's own key as the subject key.
        CertificateRequest req = interKey switch
        {
            RSA rsaInter => new CertificateRequest(dn, rsaInter, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ecdsaInter => new CertificateRequest(dn, ecdsaInter, HashAlgorithmName.SHA256),
            _ => throw new ArgumentException("Unsupported key type")
        };

        // an intermediate CA is still a CA, so we set cert to true. For best practice security, the constraints should be 0 / true, and critical true.
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 0, critical: true));

        // intermediate CAs can sign / revoke.
        req.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsages: X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));  // must be critical for a CA

        // they can also be used to authenticate server / clients.
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            enhancedKeyUsages: [
                new Oid(EKU_SERVER_AUTH_OID), // serverAuth - allows root CA to validate server certificates i.e. for web servers
                new Oid(EKU_CLIENT_AUTH_OID)  // clientAuth - allows root CA to validate client certificates i.e. for user authentication (mutual TLS)
            ],
            critical: false));

        // add subject key identifier
        byte[] skid = CalculateSubjectKeyIdentifier(interKey);
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(skid, false));

        // it cannot be valid before the root
        DateTimeOffset notBefore = rootCert.NotBefore;
        DateTimeOffset notAfter = notBefore.Add(MinicaOptions.ConvertExpiryStringToTimeSpan(options.IntermediateCaExpiry)); // ensure it is valid for the specified number of years/months/days

        // AKI must point to the ISSUER (root) key id
        byte[] issuerKeyId = ExtractSubjectKeyIdentifier(rootCert);

        // some tooling/linting expects AKI = issuer SKID. (OID 2.5.29.35)
        req.CertificateExtensions.Add(BuildAuthorityKeyIdentifierFromKeyId(issuerKeyId));

        // Create unsigned (except for issuer signature) cert, then attach SAME private key.
        var intermediatePublicCert = req.Create(rootCert, notBefore, notAfter, GenerateSerialNumber());

        X509Certificate2 intermediateCACert = interKey switch
        {
            RSA rsaInter => intermediatePublicCert.CopyWithPrivateKey(rsaInter),
            ECDsa ecdsaInter => intermediatePublicCert.CopyWithPrivateKey(ecdsaInter),
            _ => throw new ArgumentException("Unsupported key type")
        };


        // write the intermediate CA certificate in PEM as .crt and write the private key as .key
        string pemCert = ExportCertificateToPem(intermediateCACert);
        WriteAndApplyFilePermissions(options.IntermediateCACertFilePath, pemCert);
        WriteAndApplyFilePermissions(options.IntermediateCAKeyFilePath, ExportPrivateKeyToPem(interKey));

        string serial = intermediateCACert.GetSerialNumberString().ToLower();
        LogCACertificateFilePathToConsole("Intermediate CA", Path.GetFullPath(options.IntermediateCACertFilePath), Path.GetFullPath(options.IntermediateCAKeyFilePath), serial);
    }

    /// <summary>
    /// Provides random serial number generator for certificates.
    /// </summary>
    /// <returns>A random serial number.</returns>
    private static byte[] GenerateSerialNumber()
    {
        byte[] serialNumber = new byte[16];
        using var rng = RandomNumberGenerator.Create();

        rng.GetBytes(serialNumber);

        // ensure positive number
        serialNumber[0] &= 0x7F;

        return serialNumber;
    }

    /// <summary>
    /// Constructs the distinguished name string for the certificate.
    /// </summary>
    /// <param name="options"></param>
    /// <param name="commonName">What appears in the "CN=",</param>
    /// <param name="isLeaf">Indicates DN is for a leaf.</param>
    /// <returns></returns>
    private static string GetDistinguishedName(MinicaOptions options, string commonName, bool isLeaf)
    {
        // build the full distinguished name string

        // CN is mandatory
        var dnBuilder = new List<string>
        {
            $"CN={commonName}"
        };

        // add other fields if they are specified

        // add the organisational unit (OU) if specified
        if (isLeaf && !string.IsNullOrWhiteSpace(options.OrganisationalUnit))
        {
            dnBuilder.Add($"OU={options.OrganisationalUnit}");
        }

        // add the organisation (O) if specified
        if (!string.IsNullOrWhiteSpace(options.Organisation))
        {
            dnBuilder.Add($"O={options.Organisation}");
        }

        // add the country (C) if specified
        if (isLeaf && !string.IsNullOrWhiteSpace(options.Country))
        {
            dnBuilder.Add($"C={options.Country}");
        }

        // return the distinguished name as a comma-separated string
        return string.Join(", ", dnBuilder);
    }

    /// <summary>
    /// Exports the certificate to PEM format.
    /// </summary>
    /// <param name="certificate"></param>
    /// <returns></returns>
    private static string ExportCertificateToPem(X509Certificate2 certificate)
    {
        byte[] certBytes = certificate.RawData;

        return "-----BEGIN CERTIFICATE-----\n" +
              $"{Convert.ToBase64String(certBytes, Base64FormattingOptions.InsertLineBreaks)}\n" +
               "-----END CERTIFICATE-----\n";
    }

    /// <summary>
    /// Calculates the Subject Key Identifier (SKID) for the given key.
    /// </summary>
    /// <param name="key"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"></exception>
    private static byte[] CalculateSubjectKeyIdentifier(AsymmetricAlgorithm key)
    {
        byte[] publicKeyBytes;

        // the public key bytes depend on the key type...
        if (key is RSA rsa)
        {
            publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
        }
        else if (key is ECDsa ecdsa)
        {
            publicKeyBytes = ecdsa.ExportSubjectPublicKeyInfo();
        }
        else
        {
            throw new ArgumentException("Unsupported key type");
        }

        // Calculate SHA-1 hash of the public key for SKID
        return SHA1.HashData(publicKeyBytes);
    }

    /// <summary>
    /// Reads a private key from the given PEM contents.
    /// </summary>
    /// <param name="pemContents"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"></exception>
    private static AsymmetricAlgorithm ReadPrivateKey(string pemContents)
    {
        if (pemContents.Contains("-----BEGIN PRIVATE KEY-----"))
        {
            string base64 = ExtractPemContent(pemContents, "PRIVATE KEY");
            byte[] keyBytes = Convert.FromBase64String(base64);

            // Try RSA first
            try
            {
                RSA rsa = RSA.Create();
                rsa.ImportPkcs8PrivateKey(keyBytes, out _);
                return rsa;
            }
            catch
            {
                // Try ECDSA
                ECDsa ecdsa = ECDsa.Create();
                ecdsa.ImportPkcs8PrivateKey(keyBytes, out _);
                return ecdsa;
            }
        }

        // import rsa or ec private key in traditional format

        // RSA PRIVATE KEY is PKCS#1
        if (pemContents.Contains("-----BEGIN RSA PRIVATE KEY-----"))
        {
            string base64 = ExtractPemContent(pemContents, "RSA PRIVATE KEY");
            byte[] keyBytes = Convert.FromBase64String(base64);
            RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(keyBytes, out _);
            return rsa;
        }

        // EC PRIVATE KEY is SEC 1
        if (pemContents.Contains("-----BEGIN EC PRIVATE KEY-----"))
        {
            string base64 = ExtractPemContent(pemContents, "EC PRIVATE KEY");
            byte[] keyBytes = Convert.FromBase64String(base64);
            ECDsa ecdsa = ECDsa.Create();
            ecdsa.ImportECPrivateKey(keyBytes, out _);
            return ecdsa;
        }

        throw new ArgumentException("Unsupported private key format");
    }

    /// <summary>
    /// Reads a certificate from the given PEM contents.
    /// </summary>
    /// <param name="pemContents"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"></exception>
    private static X509Certificate2 ReadCertificate(string pemContents)
    {
        if (pemContents.Contains("-----BEGIN CERTIFICATE-----"))
        {
            string base64 = ExtractPemContent(pemContents, "CERTIFICATE");
            byte[] certBytes = Convert.FromBase64String(base64);

            return X509CertificateLoader.LoadCertificate(certBytes);
        }

        throw new ArgumentException("Invalid certificate format");
    }

    /// <summary>
    /// Extracts the content of a PEM block given the PEM string and the type (e.g., "CERTIFICATE", "PRIVATE KEY").
    /// </summary>
    /// <param name="pem"></param>
    /// <param name="type"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"></exception>
    private static string ExtractPemContent(string pem, string type)
    {
        string startMarker = $"-----BEGIN {type}-----";
        string endMarker = $"-----END {type}-----";

        int start = pem.IndexOf(startMarker) + startMarker.Length;
        int end = pem.IndexOf(endMarker);

        if (start < startMarker.Length || end < 0)
            throw new ArgumentException($"Invalid PEM format for {type}");

        return pem[start..end].Replace("\n", "").Replace("\r", "").Replace(" ", "");
    }

    /// <summary>
    /// Signs a certificate with the given issuer, domains, and IP addresses. It can create either a server or client certificate.
    /// The signed certificate and key are saved in a folder named after the common name (CN).
    /// </summary>
    /// <param name="issuer"></param>
    /// <param name="domains"></param>
    /// <param name="ipAddresses"></param>
    /// <param name="algorithm"></param>
    /// <param name="options"></param>
    /// <exception cref="ArgumentException"></exception>
    private static void SignCertificate(Issuer issuer, string[] domains, string[] ipAddresses, CertificateAlgorithm algorithm, MinicaOptions options)
    {
        string? commonName;

        if (options.IsClientCert)
        {
            commonName = options.User; // client cert must have a user
        }
        else
        {
            commonName = domains.FirstOrDefault() ?? ipAddresses.FirstOrDefault(); // server cert, use first domain or IP address, whichever is populated choosing domains first            
        }

        if (commonName is null) throw new ArgumentException("You must specify at least one domain name, IP address, or user.");

        // make the key for the leaf certificate

        string leafPrivateKeyFolder = options.LeafKeyFilePath;

        var key = MakeKey(leafPrivateKeyFolder, algorithm);

        var request = CreateCertificateRequest(key: key, distinguishedName: new(GetDistinguishedName(options, commonName, isLeaf: true), X500DistinguishedNameFlags.UseUTF8Encoding));

        var sanBuilder = ConstructSubjectAlternativeName(domains, ipAddresses, options);

        request.CertificateExtensions.Add(sanBuilder.Build());

        AddKeyUsageToRequest(options, request);

        var oids = CreateOidList(options);

        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(enhancedKeyUsages: oids, critical: false)); // serverAuth or clientAuth

        // no length constraint on end entity certs
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: false));

        // After BasicConstraints for end-entity certs:
        byte[] leafSkid = CalculateSubjectKeyIdentifier(key);

        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(leafSkid, false));

        // AKI must point to the ISSUER (intermediate) key id        
        try
        {
            byte[] issuerSkid = ExtractSubjectKeyIdentifier(issuer.Certificate);
            request.CertificateExtensions.Add(BuildAuthorityKeyIdentifierFromKeyId(issuerSkid)); // add AKI to leaf

        }
        catch
        {
            // Non-fatal: if issuer lacked SKID (should not happen with generated CAs), skip AKI
        }

        // generate a random serial number
        byte[] serialNumber = GenerateSerialNumber();

        // create notBefore backdated a few minutes from now for clock skew (e.g. UtcNow - 5m) but never earlier than issuer.NotBefore.
        DateTimeOffset notBefore = issuer.Certificate.NotBefore;

        if (notBefore < DateTimeOffset.UtcNow - TimeSpan.FromMinutes(5))
        {
            notBefore = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(5); // backdate 5 minutes to allow for clock skew
        }

        X509Certificate2 certificate = request.Create(issuer.Certificate, notBefore, notBefore.Add(MinicaOptions.ConvertExpiryStringToTimeSpan(options.LeafCertExpiry)), serialNumber);

        WriteTheCertificate(options, commonName, key, certificate);

        // final success message

        Log.Info("");

        if (!_failedVerification)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Log.Info("Success");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Log.Info("Warning (certificate verification failed, see warnings in the .txt)");
            Environment.ExitCode = 2; // warning
        }

        Console.ResetColor();

        if (commonName.Contains('*')) commonName = commonName.Replace("*", "wildcard"); // replace * with "wildcard" for file/folder name

        // write metadata JSON file about the generated certificate
        WriteCertificateInfoToJson(issuer, domains, ipAddresses, options, commonName, certificate);

        // write a README.txt to help the user add the cert to the Windows cert store
        AddReadMeFileToHelpUser(options, commonName);
    }

    /// <summary>
    /// Adds the appropriate Key Usage extension to the certificate request based on the algorithm used.
    /// </summary>
    /// <param name="options"></param>
    /// <param name="request"></param>
    private static void AddKeyUsageToRequest(MinicaOptions options, CertificateRequest request)
    {
        if (options.CaAlg == "ecdsa")
            request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsages: X509KeyUsageFlags.DigitalSignature, critical: false));
        else
            request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsages: X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: false));
    }

    /// <summary>
    /// Returns an OidCollection containing the appropriate Extended Key Usage (EKU) OIDs based on whether the certificate is for a client or server.
    /// </summary>
    /// <param name="options"></param>
    /// <returns></returns>
    private static OidCollection CreateOidList(MinicaOptions options)
    {
        // add extended key usage
        // https://docs.digicert.com/en/trust-lifecycle-manager/define-policies-to-ensure-compliance/certificate-attributes-and-extensions/extended-key-usage.html

        var oids = new OidCollection();

        if (options.IsClientCert)
        {
            oids.Add(new Oid(EKU_CLIENT_AUTH_OID)); // User Authentication - allows root CA to validate client certificates i.e. for user authentication (mutual TLS)
        }
        else
        {
            // copilot suggests adding both client and server auth, which is actually a good idea for a server cert
            // but it also when asked to review said "don't"! Therefore we make it optional via a flag.
            if (options.AddClientAuthEKUToServerCert)
            {
                oids.Add(new Oid(EKU_CLIENT_AUTH_OID));
                Log.Warn("Adding Client Auth EKU to a server certificate is unusual, ensure you know what you are doing.");
            }

            oids.Add(new Oid(EKU_SERVER_AUTH_OID));
        }

        return oids;
    }

    /// <summary>
    /// Creates a CertificateRequest based on the provided key and distinguished name.
    /// It supports both RSA and ECDsa keys.
    /// </summary>
    /// <param name="key"></param>
    /// <param name="distinguishedName"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException">Thrown when the key type is unsupported.</exception>
    private static CertificateRequest CreateCertificateRequest(AsymmetricAlgorithm key, X500DistinguishedName distinguishedName)
    {
        CertificateRequest request;

        if (key is RSA rsa)
        {
            request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        else if (key is ECDsa ecdsa)
        {
            request = new CertificateRequest(distinguishedName, ecdsa, HashAlgorithmName.SHA256);
        }
        else
        {
            throw new ArgumentException("Unsupported key type");
        }

        return request;
    }

    /// <summary>
    /// Constructs the Subject Alternative Name (SAN) extension for the certificate using the provided domains and IP addresses, and includes user information if it's a client certificate.
    /// </summary>
    /// <param name="domains"></param>
    /// <param name="ipAddresses"></param>
    /// <param name="options"></param>
    /// <returns></returns>
    private static SubjectAlternativeNameBuilder ConstructSubjectAlternativeName(string[] domains, string[] ipAddresses, MinicaOptions options)
    {
        // Add SAN extension
        SubjectAlternativeNameBuilder sanBuilder = new();

        if (options.IsClientCert)
        {
            // if we are making a client cert, and it is an email address, add the email as a SAN
            if (options.User!.Contains('@'))
            {
                // add rfc822 for broader compatibility
                var parts = options.User.Split('@', 2);

                if (parts.Length == 2) sanBuilder.AddEmailAddress(options.User);
            }

            sanBuilder.AddUserPrincipalName(options.User!); // user is not null here, because of the isClientCert check copilot said remove 00:44 2025-09-06
        }

        foreach (string domain in domains)
        {
            sanBuilder.AddDnsName(domain);
        }

        foreach (string ip in ipAddresses)
        {
            sanBuilder.AddIpAddress(IPAddress.Parse(ip));
        }

        return sanBuilder;
    }

    /// <summary>
    /// Includes metadata about the generated certificate in a JSON file.
    /// </summary>
    /// <param name="issuer"></param>
    /// <param name="domains"></param>
    /// <param name="ipAddresses"></param>
    /// <param name="options"></param>
    /// <param name="commonName"></param>
    /// <param name="certificate"></param>
    private static void WriteCertificateInfoToJson(Issuer issuer, string[] domains, string[] ipAddresses, MinicaOptions options, string commonName, X509Certificate2 certificate)
    {
        // write a JSON metadata file for the certificate
        var metadata = new
        {
            Generation = new
            {
                Tool = "MiniCA",
                Version = typeof(Program).Assembly.GetName().Version?.ToString() ?? "unknown",
                When = DateTimeOffset.UtcNow.ToString("o"),
                // flag if we generated the root or intermediate CA during this run
                GeneratedRootCA = _generatedRootCA,
                GeneratedIntermediateCA = _generatedIntermediateCA,
                GeneratedLeafCert = _generatedLeafCert,
                // if we failed verification at any point, this is false - automation now knows
                Success = !_failedVerification
            },
            CommonName = commonName,
            Domains = domains,
            IPAddresses = ipAddresses,
            Type = (options.IsClientCert ? "client" : "server"),
            options.User,
            options.Organisation,
            options.OrganisationalUnit,
            options.Country,
            certificate.NotBefore,
            certificate.NotAfter,
            SerialNumber = Convert.ToHexString(certificate.GetSerialNumber()).ToLower(),
            Thumbprint = certificate.Thumbprint?.ToLower(),
            CertificateFilePath = options.LeafCertFilePath,
            PrivateKeyFilePath = options.LeafKeyFilePath,
            FullChainCertificateFilePath = options.LeafFullChainCertFilePath,
            FullChainPrivateKeyFilePath = options.LeafFullChainKeyFilePath,
            Expiry = options.LeafCertExpiry,
            Issuer = new
            {
                issuer.Certificate.Subject,
                SerialNumber = Convert.ToHexString(issuer.Certificate.GetSerialNumber()).ToLower(),
                Thumbprint = issuer.Certificate.Thumbprint?.ToLower(),
                issuer.Certificate.NotBefore,
                issuer.Certificate.NotAfter,
                CertificateFilePath = issuer.CertificateFilePath,
                PrivateKeyFilePath = issuer.CertificateKeyFilePath,
                Expiry = options.CreateIntermediateCA ? options.IntermediateCaExpiry : options.CaExpiry,
            },
            Root = new
            {
                Subject = "CN=" + options.FullCAName,
                options.SuffixRandomExtensionToCAName,
                RootCACertificateFilePath = Path.GetFullPath(options.RootCACertFilePath), // validated to be .crt
                RootCAPrivateKeyFilePath = Path.GetFullPath(options.RootCAKeyFilePath), // validated to be .key
                options.CaAlg,
                Expiry = options.CaExpiry
            }
        };

        string metadataJson = JsonSerializer.Serialize(metadata, IndentedJsonOptions);

        // write to same folder as the cert, with .json extension
        WriteAndApplyFilePermissions(Path.Combine(Path.GetDirectoryName(options.LeafCertFilePath)!, $"{commonName}.json"), metadataJson);
    }

    /// <summary>
    /// Informs the user how to add the generated certificate to the Windows certificate store.
    /// </summary>
    /// <param name="options"></param>
    /// <param name="cn"></param>
    private static void AddReadMeFileToHelpUser(MinicaOptions options, string cn)
    {
        File.WriteAllText(Path.Combine(Path.GetDirectoryName(options.LeafCertFilePath)!, "README.txt"),
            "Assuming you are using Windows, and are local to the certificates...\n\n" +
            "To add to the certificate store (on Windows):\n\n" +
            "certutil -addstore -user \"Root\" minica.crt" + "\n" +
            "certutil -addstore -user \"CA\" minica-intermediate.crt" + "\n" +
            (options.IsClientCert ?
                ($"Import-PfxCertificate -FilePath \"{cn}.p12\" -CertStoreLocation Cert:\\CurrentUser\\My -Password (ConvertTo-SecureString -String \"Password123\" -AsPlainText -Force)\n" +
                $"where Password123 is the password for the certificate; use PowerShell as admin.\n") :
                $"certutil -addstore -user \"My\" {cn}.crt\n") +
            "\n" +
            "To view the certificates, you can use the following command:\n" +
            "certutil -store -user \"Root\"\n" +
            "\n" +
            "Note: Make sure to have the necessary permissions to add certificates to the store.\n");
    }

    /// <summary>
    /// Writes the generated certificate and key files to the specified folder.
    /// </summary>
    /// <param name="options"></param>
    /// <param name="commonName"></param>
    /// <param name="key"></param>
    /// <param name="certificate"></param>
    private static void WriteTheCertificate(MinicaOptions options, string commonName, AsymmetricAlgorithm key, X509Certificate2 certificate)
    {
        string pemCert = ExportCertificateToPem(certificate);

        string crtPath = options.LeafCertFilePath;
        string keyPath = options.LeafKeyFilePath;
        string fullChainCertPath = options.LeafFullChainCertFilePath;
        string fullChainKeyPath = options.LeafFullChainKeyFilePath;

        // Build proper full chain: leaf + intermediate(s); root optional
        var chainParts = new List<string> { pemCert }; // leaf

        // If intermediate exists, add it
        if (File.Exists(options.IntermediateCACertFilePath))
        {
            chainParts.Add(File.ReadAllText(options.IntermediateCACertFilePath));
        }

        // we need the top-level root CA cert at the end of the chain for proper validation by clients
        chainParts.Add(File.ReadAllText(options.RootCACertFilePath));

        // Full chain leaf -> intermediate -> root | leaf -> root
        string fullChain = string.Join("\n", chainParts);

        // write if it doesn't exist
        // Write CRT/KEY files (same content, different extension)
        if (!File.Exists(crtPath) || !File.Exists(keyPath) || !File.Exists(fullChainCertPath) || !File.Exists(fullChainKeyPath))
        {
            // if we write the .crt, we write the .key and .fullchain.key too - so they are in sync
            WriteAndApplyFilePermissions(crtPath, pemCert);
            WriteAndApplyFilePermissions(keyPath, ExportPrivateKeyToPem(key));
            WriteAndApplyFilePermissions(fullChainCertPath, fullChain);
            WriteAndApplyFilePermissions(fullChainKeyPath, ExportPrivateKeyToPem(key));

            _generatedLeafCert = true;
        }
        else
        {
            Log.Warn($"{crtPath} already exists - not overwriting");
            Log.Warn($"{keyPath} already exists - not overwriting");
            Log.Warn($"{fullChainCertPath} already exists - not overwriting");
            Log.Warn($"{fullChainKeyPath} already exists - not overwriting");
        }

        Log.Info("");

        Console.BackgroundColor = ConsoleColor.Red;
        Console.ForegroundColor = ConsoleColor.Black;
        Log.Info($" {commonName} ", false);
        Console.ResetColor();
        Log.Info(" ");

        LogBlueBullet("SERIAL #", certificate.GetSerialNumberString());
        LogBlueBullet("CERTIFICATE", Path.GetFullPath(crtPath));
        LogBlueBullet("PRIVATE KEY", Path.GetFullPath(keyPath));
        LogBlueBullet("CHAIN CERT", Path.GetFullPath(fullChainCertPath));
        LogBlueBullet("CHAIN KEY", Path.GetFullPath(fullChainKeyPath));

        Log.Info("");

        if (options.IsClientCert)
        {
            WriteUserP12Certificate(options, key, certificate);
        }
        else
        {
            ThisCertificateIsFor("SERVER");
        }

        VerifyItCreatedPerfectCertificates(options, crtPath, fullChainCertPath);
    }

    /// <summary>
    /// There is a lot of logic, and many ways to get it wrong, so we apply some checks and output the results to the user.
    /// The ChainDumper tool analyses the certificate and its chain, and outputs any issues it finds.
    /// </summary>
    /// <param name="options"></param>
    /// <param name="crtPath"></param>
    /// <param name="fullChainCertPath"></param>
    private static void VerifyItCreatedPerfectCertificates(MinicaOptions options, string crtPath, string fullChainCertPath)
    {
        // Output the cert chain to the console for user inspection
        string fullChainPathForDump = options.LeafFullChainCertFilePath + ".txt";
        string fullChainAnalysis = CertChainDumper.ReadAndExplainCertificate(fullChainCertPath);
        File.WriteAllText(fullChainPathForDump, fullChainAnalysis);

        // if there are any errors, warn the user to check the file
        if (fullChainAnalysis.Contains("ERROR", StringComparison.CurrentCultureIgnoreCase))
        {
            _failedVerification = true;
            Log.Warn("The full chain certificate has issues, please check the file:");
            Log.Warn(fullChainPathForDump);
        }

        string crtPathForDump = options.LeafCertFilePath + ".txt";
        string crtAnalysis = CertChainDumper.ReadAndExplainCertificate(crtPath);
        File.WriteAllText(crtPathForDump, crtAnalysis);

        // if there are any errors, warn the user to check the file
        if (crtAnalysis.Contains("ERROR", StringComparison.CurrentCultureIgnoreCase))
        {
            _failedVerification = true;
            Log.Warn("The leaf certificate has issues, please check the file:");
            Log.Warn(crtPathForDump);
        }
    }

    /// <summary>
    /// Outputs to the console whether the certificate is for a server or client.
    /// </summary>
    /// <param name="type"></param>
    private static void ThisCertificateIsFor(string type)
    {
        Log.Info("");
        Log.Info("This is a ", false);
        Console.BackgroundColor = ConsoleColor.Green;
        Console.ForegroundColor = ConsoleColor.Black;
        Log.Info($" {type} ", false);
        Console.ResetColor();
        Log.Info(" certificate.");
    }

    /// <summary>
    /// Writes a user P12 certificate for client authentication.
    /// </summary>
    /// <param name="options"></param>
    /// <param name="key"></param>
    /// <param name="certificate"></param>
    /// <exception cref="ArgumentException"></exception>
    private static void WriteUserP12Certificate(MinicaOptions options, AsymmetricAlgorithm key, X509Certificate2 certificate)
    {
        ThisCertificateIsFor("CLIENT");

        // turn the certificate into a p12 file for browsers and other uses
        // equivalent openssl command: 
        // openssl pkcs12 -export -out dave@mysite.io.p12 -inkey dave@mysite.io.key -in dave@mysite.io.crt -certfile minica.crt -name "dave@mysite.io" -passout pass:Password123
        string p12Path = options.LeafP12FilePath;

        if (File.Exists(p12Path))
        {
            Log.Warn($"{p12Path} already exists - not overwriting");
            return; // don't overwrite
        }

        var certWithKey = key switch
        {
            RSA rsa => certificate.CopyWithPrivateKey(rsa),
            ECDsa ecdsa => certificate.CopyWithPrivateKey(ecdsa),
            _ => throw new ArgumentException("Unsupported key type")
        };

        // Export the certificate and private key to a PFX/PKCS#12 file - password protected
        var pfxBytes = certWithKey.Export(X509ContentType.Pkcs12, options.P12Password);

        WriteAndApplyFilePermissions(p12Path, pfxBytes);
    }

    /// <summary>
    /// Writes the specified contents to a file and applies secure file permissions on Unix-like systems.
    /// </summary>
    /// <param name="filename"></param>
    /// <param name="contents"></param>
    /// <exception cref="ArgumentNullException"></exception>
    private static void WriteAndApplyFilePermissions(string filename, byte[]? contents)
    {
        ArgumentNullException.ThrowIfNull(contents);

        File.WriteAllBytes(filename, contents);

        // Set file permissions on Unix-like systems only
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(filename, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    /// <summary>
    /// Writes the specified contents to a file and applies secure file permissions on Unix-like systems.
    /// </summary>
    /// <param name="filename"></param>
    /// <param name="contents"></param>
    private static void WriteAndApplyFilePermissions(string filename, string contents)
    {
        File.WriteAllText(filename, contents);

        // Set file permissions on Unix-like systems only
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(filename, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    /// <summary>
    /// Creates an X509Extension for Authority Key Identifier (AKI) from the given key identifier (SKID).
    /// </summary>
    /// <param name="keyId"></param>
    /// <returns></returns>
    private static X509Extension BuildAuthorityKeyIdentifierFromKeyId(byte[] keyId)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();

        // [0] IMPLICIT OCTET STRING
        var keyIdTag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: false);
        writer.WriteOctetString(keyId, keyIdTag);

        writer.PopSequence();

        // OID for Authority Key Identifier is 2.5.29.35
        return new X509Extension("2.5.29.35", writer.Encode(), critical: false);
    }

    /// <summary>
    /// Extracts the Subject Key Identifier (SKID) from the given certificate.
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    private static byte[] ExtractSubjectKeyIdentifier(X509Certificate2 cert)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509SubjectKeyIdentifierExtension skidExt)
            {
                if (skidExt.SubjectKeyIdentifier is null)
                {
                    continue; // should not happen, but be robust
                }

                // Hex string -> bytes
                string hex = skidExt.SubjectKeyIdentifier.Replace(":", "").Replace(" ", "");
                return Convert.FromHexString(hex);
            }
        }

        // Fallback: recompute from public key
#pragma warning disable SYSLIB0027 // Type or member is obsolete. It's a fallback for old certs.
        using AsymmetricAlgorithm pub = cert.PublicKey.Key;
#pragma warning restore SYSLIB0027 // Type or member is obsolete

        return CalculateSubjectKeyIdentifier(pub);
    }
}