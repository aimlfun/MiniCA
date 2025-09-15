using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MiniCA;

/// <summary>
/// Represents an issuer for a certificate authority (CA).
/// </summary>
public class Issuer
{
    /// <summary>
    /// The key used by the issuer to sign certificates.
    /// </summary>
    public required AsymmetricAlgorithm Key { get; set; }

    /// <summary>
    /// The certificate issued by the issuer.
    /// </summary>
    public required X509Certificate2 Certificate { get; set; }

    /// <summary>
    /// The file path where the issuer's certificate is stored.
    /// </summary>
    public string CertificateFilePath { get; set; } = string.Empty;

    /// <summary>
    /// The file path where the issuer's private key is stored.
    /// </summary>
    public string CertificateKeyFilePath { get; set; } = string.Empty;
}
