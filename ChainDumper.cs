using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Linq;

namespace MiniCA;

/// <summary>
/// Provides functionality to read and explain certificate chains from files.
/// This includes parsing PEM files, extracting certificate details, and performing in-memory chain validation.
/// 
/// I created much of this using the awesome GitHub Copilot tool! So no claims to originality.
/// </summary>
internal static class CertChainDumper
{
    /// <summary>
    /// Outputs the certificate chain details for the certificates found in the specified file.
    /// </summary>
    /// <param name="filename"></param>
    /// <returns></returns>
    internal static string ReadAndExplainCertificate(string filename)
    {
        if (!File.Exists(filename))
        {
            Log.Error($"Unable to write certificate chain: File not found: {filename}");
            return $"Unable to write certificate chain: File not found: {filename}";
        }

        StringBuilder output = new();

        // read the file, and extract all certificates (there can be multiple in a PEM file)
        string fileContent = File.ReadAllText(filename);
        var certs = ExtractCertificates(fileContent);

        if (certs.Count > 1)
        {
            output.AppendLine($"{certs.Count} certificates (chain) in file: {filename}");
        }
        else if (certs.Count == 1)
        {
            output.AppendLine($"1 certificate found in file: {filename}");
        }
        else
        {
            return $"No certificates found in file: {filename}";
        }

        DateTime nowLocal = DateTime.Now;
        DateTime nowUtc = DateTime.UtcNow;

        // set a flag if local time is different to UTC by more than a second or 2 (i.e. so we display both)
        bool showBothTimes = Math.Abs((nowLocal - nowUtc).TotalSeconds) > 2;

        // there can be multiple certificates in the file...
        for (int certIndex = 0; certIndex < certs.Count; certIndex++)
        {
            List<string> notes = [];

            X509Certificate2 certificate = certs[certIndex];

            output.AppendLine($"\nCERTIFICATE #{certIndex + 1}");

            OutputCertPurpose(output, certificate);

            output.AppendLine($"  Subject:              {certificate.Subject}");
            output.AppendLine($"  Issuer:               {GetIssuerDisplay(certificate)}");

            OutputValidFromAndTo(output, nowLocal, showBothTimes, certificate);

            output.AppendLine($"  Thumbprint:           {certificate.Thumbprint.ToLower()}");
            output.AppendLine($"  Serial Number:        {certificate.GetSerialNumberString().ToLower()}");
            output.AppendLine($"  Signature Algorithm:  {GetNormalizedSignatureAlg(certificate)}");
            output.AppendLine($"  Public Key Algorithm: {GetNormalizedPublicKeyAlg(certificate)}");

            OutputEnhancedKeyUsage(output, certificate, out var ekuList); // what is this cert for? server auth, client auth etc

            OutputKeyUsage(output, certificate); // what can the key be used for? digital signature, key encipherment etc

            bool foundBasicConstraints = false;

            // what other extensions are present?
            foreach (var extension in certificate.Extensions)
            {
                if (extension is X509BasicConstraintsExtension)
                {
                    OutputBasicConstraintExtension(output, extension, notes);
                    foundBasicConstraints = true;
                }

                if (extension is X509SubjectAlternativeNameExtension san)
                {
                    OutputSanExtension(output, san);
                }
            }

            if (!foundBasicConstraints)
            {
                notes.Add("No Basic Constraints extension found.  This will be treated as end-entity by modern TLS stacks.");
            }

            OutputEkuUsageNote(ekuList, notes);

            OutputNotes(output, notes);
        }

        // Chain validation summary (#12)
        try
        {
            if (certs.Count > 1) // with 1 cert, chain validation is not very interesting, and will complain about untrusted root
                OutputInMemoryChainValidation(output, certs);
        }
        catch (Exception ex)
        {
            output.AppendLine();
            output.AppendLine("[ERROR] Chain Validation:");
            output.AppendLine($"  {ex.GetType().Name}: {ex.Message}");
        }

        // dispose all certs (we loaded them into memory)
        foreach (X509Certificate2 cert in certs)
        {
            cert.Dispose();
        }

        return output.ToString();
    }

    /// <summary>
    /// Writes the Valid From and Valid To dates in both local and UTC formats, with notes if not yet valid or expired.
    /// </summary>
    /// <param name="output"></param>
    /// <param name="nowLocal"></param>
    /// <param name="showBothTimes"></param>
    /// <param name="certificate"></param>
    private static void OutputValidFromAndTo(StringBuilder output, DateTime nowLocal, bool showBothTimes, X509Certificate2 certificate)
    {
        string notBeforeLocal = certificate.NotBefore.ToString("u"); // "yyyy-MM-dd HH:mm:ssZ" (kind=local converted to UTC format)
        string notAfterLocal = certificate.NotAfter.ToString("u");
        string notBeforeUtc = certificate.NotBefore.ToUniversalTime().ToString("u");
        string notAfterUtc = certificate.NotAfter.ToUniversalTime().ToString("u");

        bool notYetValid = certificate.NotBefore > nowLocal;
        bool expired = certificate.NotAfter < nowLocal;

        output.AppendLine($"  Valid From (Local):   {notBeforeLocal} {(notYetValid ? " >>> NOT YET VALID << " : "")}");
        output.AppendLine($"  Valid To   (Local):   {notAfterLocal} {(expired ? " !!! EXPIRED !!!" : "")}");

        if (showBothTimes) // utc != local
        {
            output.AppendLine($"  Valid From (UTC):     {notBeforeUtc}");
            output.AppendLine($"  Valid To   (UTC):     {notAfterUtc}");
        }
    }

    /// <summary>
    /// Performs in-memory chain validation for each leaf certificate found in the provided list.
    /// </summary>
    /// <param name="output"></param>
    /// <param name="certs"></param>
    private static void OutputInMemoryChainValidation(StringBuilder output, List<X509Certificate2> certs)
    {
        output.AppendLine();
        output.AppendLine("============================");
        output.AppendLine("CERTIFICATE CHAIN VALIDATION");
        output.AppendLine("============================");
        output.AppendLine("");

        if (certs.Count == 0)
        {
            output.AppendLine("[ERROR]  No certificates to validate.");
            return;
        }

        var leafCerts = certs.Where(c => !IsCertificationAuthority(c)).ToList();

        if (leafCerts.Count == 0) leafCerts = certs; // fallback

        int idx = 0;

        foreach (var leaf in leafCerts)
        {
            idx++;
            output.AppendLine($"  Leaf #{idx}: {GetCN(leaf.Subject)}");

            // Pass A (current behavior – AllowUnknownCertificateAuthority)
            ChainBuildResult resultA = BuildChain(leaf, certs, X509VerificationFlags.AllowUnknownCertificateAuthority);
            DumpChain(output, resultA, "With AllowUnknownCertificateAuthority");
            AppendSignatureDiagnostic(output, leaf, certs, resultA);

            // Pass B (strict – show what was suppressed)
            ChainBuildResult resultB = BuildChain(leaf, certs, X509VerificationFlags.NoFlag);
            DumpChain(output, resultB, "Strict (NoFlag)");
        }
    }

    /// <summary>
    /// Results of an attempt to build a certificate chain.
    /// </summary>
    /// <param name="Built"></param>
    /// <param name="Elements"></param>
    /// <param name="AggregateIssues"></param>
    private sealed record ChainBuildResult(bool Built, List<(X509Certificate2 Cert, string Subject, string Issuer, string Status)> Elements, List<string> AggregateIssues);

    /// <summary>
    /// Builds a certificate chain for the specified leaf certificate using the provided list of all certificates.
    /// </summary>
    /// <param name="leaf"></param>
    /// <param name="all"></param>
    /// <param name="flags"></param>
    /// <returns></returns>
    private static ChainBuildResult BuildChain(X509Certificate2 leaf, List<X509Certificate2> all, X509VerificationFlags flags)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = flags;

        // Force custom trust: only roots you explicitly add are trusted.
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

        // Add everything except the leaf to ExtraStore, then pick roots (self-signed CA) for CustomTrustStore.
        foreach (var c in all.Where(c => !ReferenceEquals(c, leaf)))
        {
            chain.ChainPolicy.ExtraStore.Add(c);
        }

        // self-signed root candidate to be a trust anchor in the custom trust store
        foreach (var c in all.Where(c => c.Subject == c.Issuer))
        {
            chain.ChainPolicy.CustomTrustStore.Add(c);
        }

        bool built = chain.Build(leaf);

        var elems = chain.ChainElements.Cast<X509ChainElement>()
            .Select(e =>
            {
                string status = e.ChainElementStatus.Length == 0
                    ? "OK"
                    : string.Join(", ", e.ChainElementStatus.Select(s => s.StatusInformation.Trim()));

                return (e.Certificate, GetCN(e.Certificate.Subject), GetCN(e.Certificate.Issuer), status);
            }).ToList();

        var agg = chain.ChainStatus
            .Select(s => s.StatusInformation.Trim())
            .Distinct()
            .ToList();

        return new(built, elems, agg);
    }

    /// <summary>
    /// Dumps the certificate chain validation results to the specified output.
    /// </summary>
    /// <param name="output"></param>
    /// <param name="chainBuildResult"></param>
    /// <param name="label"></param>
    private static void DumpChain(StringBuilder output, ChainBuildResult chainBuildResult, string label)
    {
        output.AppendLine($"    {label}: {(chainBuildResult.Built ? "Success" : "Failed")}");

        for (int i = 0; i < chainBuildResult.Elements.Count; i++)
        {
            var e = chainBuildResult.Elements[i];
            output.AppendLine($"      [{i}] Subject={e.Subject}; Issuer={e.Issuer}; Status={e.Status}");
        }

        if (!chainBuildResult.Built && chainBuildResult.AggregateIssues.Count > 0)
            output.AppendLine($"      Issues: {string.Join("; ", chainBuildResult.AggregateIssues)}");
    }

    /// <summary>
    /// Outputs any notes collected during the analysis of the certificate.
    /// </summary>
    /// <param name="output"></param>
    /// <param name="notes"></param>
    private static void OutputNotes(StringBuilder output, List<string> notes)
    {
        if (notes.Count == 0)
        {
            return;
        }

        output.AppendLine("  Notes:");

        for (int i = 0; i < notes.Count; i++)
        {
            output.AppendLine("    " + notes[i]);
        }
    }

    /// <summary>
    /// Outputs whether the certificate is a ROOT CA, INTERMEDIATE CA, or end-entity certificate.
    /// </summary>
    /// <param name="output"></param>
    /// <param name="cert"></param>
    private static void OutputCertPurpose(StringBuilder output, X509Certificate2 cert)
    {
        if (IsCertificationAuthority(cert))
        {
            if (cert.Subject.Equals(cert.Issuer, StringComparison.OrdinalIgnoreCase))
            {
                output.AppendLine("  [This is a ROOT CA certificate]");
            }
            else
            {
                output.AppendLine("  [This is an INTERMEDIATE CA certificate]");
            }
        }
        else
        {
            output.AppendLine("  [This is an end-entity certificate]");
        }
    }

    /// <summary>
    /// Outputs the Basic Constraints extension details, with notes on CA capabilities.
    /// </summary>
    /// <param name="output"></param>
    /// <param name="extension"></param>
    /// <param name="notes"></param>
    private static void OutputBasicConstraintExtension(StringBuilder output, X509Extension extension, List<string> notes)
    {
        // decode critical depth etc
        X509BasicConstraintsExtension basicConstraint = (X509BasicConstraintsExtension)extension;
        string pathLenDisplay = basicConstraint.CertificateAuthority
            ? (basicConstraint.PathLengthConstraint >= 0 ? basicConstraint.PathLengthConstraint.ToString() : "Unlimited")
            : "N/A";

        output.AppendLine($"  Basic Constraints:    Certificate Authority: {(basicConstraint.CertificateAuthority ? "Yes" : "No")}, Path Length Constraint: {pathLenDisplay}, Critical: {(extension.Critical ? "Yes" : "No")}");

        if (basicConstraint.CertificateAuthority)
        {
            if (basicConstraint.PathLengthConstraint == 0)
                notes.Add("This CA certificate cannot issue CA certificates, but can issue server/client certificates.");
            else if (basicConstraint.PathLengthConstraint > 0)
                notes.Add($"This CA certificate can issue other CA certificates, but only up to a depth of {basicConstraint.PathLengthConstraint}.");
            else
                notes.Add("This CA certificate can issue subordinate CA certificates without an explicit path length limit.");
        }
    }

    /// <summary>
    /// Interprets the EKU list and adds a usage note to the output.
    /// </summary>
    /// <param name="ekuList"></param>
    /// <param name="notes"></param>
    private static void OutputEkuUsageNote(List<string> ekuList, List<string> notes)
    {
        switch (ekuList.Count)
        {
            case 0:
                notes.Add("No Enhanced Key Usages (EKUs) specified. This means the certificate can be used for any purpose.");
                break;

            default:
                if (ekuList.Contains("Server Authentication") && !ekuList.Contains("Client Authentication"))
                {
                    notes.Add("This certificate can be used for server authentication (e.g., HTTPS servers), but not for client authentication.");
                }
                else if (!ekuList.Contains("Server Authentication") && ekuList.Contains("Client Authentication"))
                {
                    notes.Add("This certificate can be used for client authentication, but not for server authentication.");
                }
                else if (ekuList.Contains("Server Authentication") && ekuList.Contains("Client Authentication"))
                {
                    notes.Add("This certificate can be used for both server and client authentication.");
                }
                break;
        }
    }

    /// <summary>
    /// Outputs the Subject Alternative Name (SAN) extension details.
    /// </summary>
    /// <param name="output"></param>
    /// <param name="san"></param>
    private static void OutputSanExtension(StringBuilder output, X509SubjectAlternativeNameExtension san)
    {
        /// Subject Alternative Name (SAN) is an extension to the X.509 specification that allows users to specify additional host names for a single SSL certificate.

        output.AppendLine("  Subject Alternative Names:");

        List<string> sanNames = [.. san.Format(true).Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries)];

        foreach (string sanName in sanNames)
        {
            output.AppendLine($"    - {sanName.Trim()}");
        }
    }

    /// <summary>
    /// EKUs are specified in the certificate to indicate one or more purposes for which the public key can be used.
    /// </summary>
    /// <param name="output"></param>
    /// <param name="cert"></param>
    private static void OutputEnhancedKeyUsage(StringBuilder output, X509Certificate2 cert, out List<string> ekuList)
    {
        ekuList = [];

        if (cert.Extensions["2.5.29.37"] is X509EnhancedKeyUsageExtension eku)
        {
            output.AppendLine("  Enhanced Key Usages:");

            foreach (System.Security.Cryptography.Oid oid in eku.EnhancedKeyUsages)
            {
                if (oid is null)
                {
                    continue;
                }

                output.AppendLine($"    - {oid.FriendlyName} ({oid.Value})");

                if (oid.FriendlyName is not null) ekuList.Add(oid.FriendlyName);
            }
        }
    }

    /// <summary>
    /// Key Usage defines the purpose (e.g., encipherment, signature) of the key contained in the certificate.
    /// </summary>
    /// <param name="output"></param>
    /// <param name="cert"></param>
    private static void OutputKeyUsage(StringBuilder output, X509Certificate2 cert)
    {
        // add key usage if present
        if (cert.Extensions["2.5.29.15"] is X509KeyUsageExtension keyUsage)
        {
            output.AppendLine("  Key Usages:");

            if (keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature))
                output.AppendLine("    - Digital Signature");

            if (keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.NonRepudiation))
                output.AppendLine("    - Non Repudiation");

            if (keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment))
                output.AppendLine("    - Key Encipherment");

            if (keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DataEncipherment))
                output.AppendLine("    - Data Encipherment");

            if (keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyAgreement))
                output.AppendLine("    - Key Agreement");

            if (keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign))
                output.AppendLine("    - Certificate Signing");

            if (keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.CrlSign))
                output.AppendLine("    - CRL Signing");

            if (keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.EncipherOnly))
                output.AppendLine("    - Encipher Only");

            if (keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DecipherOnly))
                output.AppendLine("    - Decipher Only");
        }
    }

    /// <summary>
    /// Used to extract PEM blocks from a file. There can be multiple blocks in a single file.
    /// RegEx captures the base64 content between the BEGIN and END lines.
    /// </summary>
    static readonly Regex PemCertRegex = new(
        "-----BEGIN CERTIFICATE-----(?<base64>[^-]+)-----END CERTIFICATE-----",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// Extracts all certificates from a PEM-formatted string. A PEM file can contain multiple certificates.
    /// </summary>
    /// <param name="pemContent"></param>
    /// <returns></returns>
    static List<X509Certificate2> ExtractCertificates(string pemContent)
    {
        List<X509Certificate2> list = [];

        foreach (Match m in PemCertRegex.Matches(pemContent))
        {
            string base64 = m.Groups["base64"].Value.Replace("\r", "").Replace("\n", "").Trim();

            if (base64.Length == 0) continue; // skip empty blocks

            try
            {
                list.Add(new X509Certificate2(Convert.FromBase64String(base64)));
            }
            catch (FormatException)
            {
                // skip invalid block
            }
        }

        return list;
    }

    /// <summary>
    /// Determines if a certificate is self-signed (Subject==Issuer and chain consists only of itself).
    /// Allows unknown root (common for a private CA not yet trusted).
    /// </summary>
    /// <param name="cert"></param>
    /// <param name="reason"></param>
    /// <returns></returns>
    private static bool IsSelfSigned(X509Certificate2 cert, out string reason)
    {
        reason = string.Empty;

        if (!cert.Subject.Equals(cert.Issuer, StringComparison.OrdinalIgnoreCase))
        {
            reason = "Subject != Issuer";
            return false;
        }

        using X509Chain chain = new();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

        bool built = chain.Build(cert);

        if (chain.ChainElements.Count == 1)
        {
            // Accept if only itself; statuses may include UntrustedRoot which is fine here.
            reason = built ? "Single element chain (trusted)" : "Single element chain (untrusted root)";
            return true;
        }

        reason = "Multiple elements in chain";
        return false;
    }

    /// <summary>
    /// Returns a friendly display of the issuer, or "Self-signed" if appropriate.
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    private static string GetIssuerDisplay(X509Certificate2 cert)
    {
        if (IsSelfSigned(cert, out _)) return "Self-signed";

        return GetCNFromIssuer(cert.Issuer);
    }

    /// <summary>
    /// Normalizes signature algorithm (e.g., "sha256RSA", "sha384ECDSA") with OID.
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    private static string GetNormalizedSignatureAlg(X509Certificate2 cert)
    {
        string oid = cert.SignatureAlgorithm.Value ?? "";

        string normalized = oid switch
        {
            "1.2.840.113549.1.1.5" => "sha1RSA",
            "1.2.840.113549.1.1.11" => "sha256RSA",
            "1.2.840.113549.1.1.12" => "sha384RSA",
            "1.2.840.113549.1.1.13" => "sha512RSA",
            "1.2.840.10045.4.3.2" => "sha256ECDSA",
            "1.2.840.10045.4.3.3" => "sha384ECDSA",
            "1.2.840.10045.4.3.4" => "sha512ECDSA",
            _ => cert.SignatureAlgorithm.FriendlyName ?? "Unknown"
        };
        return $"{normalized} (OID {oid})";
    }

    /// <summary>
    /// Normalizes public key algorithm and attempts to include key size / curve name.
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    private static string GetNormalizedPublicKeyAlg(X509Certificate2 cert)
    {
        string oid = cert.PublicKey.Oid?.Value ?? "";

        switch (oid)
        {
            case "1.2.840.113549.1.1.1": // RSA
                {
                    using var rsa = cert.GetRSAPublicKey();
                    int bits = rsa?.KeySize ?? 0;
                    return $"RSA {(bits > 0 ? bits + " bits" : "")} (OID {oid})";
                }
            case "1.2.840.10040.4.1": // DSA
                {
                    using var dsa = cert.GetDSAPublicKey();
                    int bits = dsa?.KeySize ?? 0;
                    return $"DSA {(bits > 0 ? bits + " bits" : "")} (OID {oid})";
                }
            case "1.2.840.10045.2.1": // ECC
                {
                    try
                    {
                        using var ecdsa = cert.GetECDsaPublicKey();
                        if (ecdsa != null)
                        {
                            var parms = ecdsa.ExportParameters(false);
                            int bits = parms.Q.X?.Length > 0 ? parms.Q.X.Length * 8 : 0;
                            string curve = bits switch
                            {
                                256 => "P-256",
                                384 => "P-384",
                                521 => "P-521",
                                _ => bits > 0 ? bits + "-bit curve" : "Unknown curve"
                            };
                            return $"ECC {curve} (OID {oid})";
                        }
                    }
                    catch
                    {
                        // ignore and fall through
                    }
                    return $"ECC (OID {oid})";
                }
            default:
                return $"{cert.PublicKey.Oid?.FriendlyName ?? "Unknown"} (OID {oid})";
        }
    }

    /// <summary>
    /// Extracts the Common Name (CN) from the issuer string.
    /// </summary>
    private static string GetCNFromIssuer(string issuer) => GetCN(issuer);

    /// <summary>
    /// Extracts the Common Name (CN) from a Distinguished Name (DN) string.
    /// </summary>
    /// <param name="dn"></param>
    /// <returns></returns>
    private static string GetCN(string dn)
    {
        var parts = dn.Split(',');
        foreach (var part in parts)
        {
            var trimmedPart = part.Trim();
            if (trimmedPart.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                return trimmedPart[3..].Trim();
        }
        return dn;
    }

    /// <summary>
    /// Returns true if the certificate is a Certification Authority (CA) certificate.
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    private static bool IsCertificationAuthority(X509Certificate2 cert)
    {
        // return true if the certificate is a CA certificate
        foreach (var extension in cert.Extensions)
        {
            if (extension is X509BasicConstraintsExtension basicConstraint && basicConstraint.CertificateAuthority)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Extracts the Subject Key Identifier (SKID) from the certificate and returns it as a lowercase hex string without colons.
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    private static string? GetSubjectKeyIdHex(X509Certificate2 cert)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509SubjectKeyIdentifierExtension skid)
                return skid.SubjectKeyIdentifier?.Replace(":", "").ToLowerInvariant();
        }

        return null; // no SKID present
    }

    /// <summary>
    /// Extracts the Authority Key Identifier (AKI) from the certificate and returns it as a lowercase hex string without colons.
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    private static string? GetAuthorityKeyIdHex(X509Certificate2 cert)
    {
        // OID 2.5.29.35
        var aki = cert.Extensions["2.5.29.35"];

        if (aki == null) return null; // no AKI present, which is probably a problem for a leaf cert

        ReadOnlySpan<byte> data = aki.RawData;

        // Minimal sanity: need at least SEQUENCE tag + length + [0] + len + >=1 byte
        if (data.Length < 5 || data[0] != 0x30) return null; // not a SEQUENCE, or too short to be valid

        int offset = 1;
        int seqLen;
        byte lenByte = data[offset++];

        if ((lenByte & 0x80) == 0)
        {
            // short form
            seqLen = lenByte;
        }
        else
        {
            int lenLen = lenByte & 0x7F;
            if (lenLen == 0 || lenLen > 2 || offset + lenLen > data.Length) return null;
            seqLen = 0;
            for (int i = 0; i < lenLen; i++)
            {
                seqLen = (seqLen << 8) | data[offset++];
            }
            if (seqLen < 0 || offset + seqLen > data.Length) return null;
        }

        // Now scan inside the SEQUENCE for context-specific tag [0] (0x80) containing the keyIdentifier
        int end = offset + seqLen;

        while (offset + 2 <= end)
        {
            byte tag = data[offset++];

            // Expect primitive context-specific 0 (0x80)
            int len;

            if (offset >= end) break;

            byte b = data[offset++];

            if ((b & 0x80) == 0)
            {
                len = b;
            }
            else
            {
                int lenLen = b & 0x7F;
 
                if (lenLen == 0 || lenLen > 2 || offset + lenLen > end) return null;
                
                len = 0;
 
                for (int i = 0; i < lenLen; i++)
                {
                    len = (len << 8) | data[offset++];
                }
            }

            if (offset + len > end) return null;

            if (tag == 0x80)
            {
                return Convert.ToHexString(data.Slice(offset, len)).ToLowerInvariant();
            }

            offset += len;
        }

        return null;
    }

    /// <summary>
    /// Adds diagnostic information about signature mismatches based on AKI/SKID comparison.
    /// </summary>
    /// <param name="output">Any warnings are added to this.</param>
    /// <param name="leaf">The certificate (leaf) to check.</param>
    /// <param name="all">All the certificates.</param>
    /// <param name="primaryResult"></param>
    private static void AppendSignatureDiagnostic(
        StringBuilder output,
        X509Certificate2 leaf,
        IEnumerable<X509Certificate2> all,
        ChainBuildResult primaryResult)
    {
        // detect actual signature failure in the first pass
        bool signatureFailure = !primaryResult.Built &&
            (primaryResult.AggregateIssues.Any(i => i.Contains("signature", StringComparison.OrdinalIgnoreCase)) ||
             primaryResult.Elements.Any(e => e.Status.Contains("signature", StringComparison.OrdinalIgnoreCase)));

        string? aki = GetAuthorityKeyIdHex(leaf);
        string? leafSkid = GetSubjectKeyIdHex(leaf);

        var issuer = all.FirstOrDefault(c => IsCertificationAuthority(c) && leaf.Issuer == c.Subject);

        if (issuer == null)
        {
            output.AppendLine("    WARNING: Issuer not present in supplied set (chain halted at leaf).");
            return;
        }

        string? issuerSkid = GetSubjectKeyIdHex(issuer);

        string warningMessage = $"    WARNING: Leaf SKID={(leafSkid ?? "none")} AKI={(aki ?? "none")} Issuer SKID={(issuerSkid ?? "none")}";

        if (aki == null)
        {
            output.AppendLine(warningMessage);
            output.AppendLine("    WARNING: Missing AKI on leaf; reissue after adding AKI extension.");
            return;
        }

        if (issuerSkid == null)
        {
            output.AppendLine(warningMessage);
            output.AppendLine("    WARNING: Issuer missing SKID (unexpected for generated CA).");
            return;
        }

        if (!aki.Equals(issuerSkid, StringComparison.OrdinalIgnoreCase))
        {
            output.AppendLine(warningMessage);
            output.AppendLine("    WARNING: AKI != Issuer SKID => leaf signed by different (older) intermediate. Reissue leaf.");
        }
        else
        {
            if (signatureFailure)
            {
                output.AppendLine(warningMessage);
                output.AppendLine("    WARNING: AKI matches issuer SKID; signature failure points to stale/corrupt leaf or mismatched issuer key.");
            }
        }

        // nothing added? all good
    }
}