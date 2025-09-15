# MiniCA

MiniCA is a lightweight, self‑contained Certificate Authority utility (C# .NET 9) for generating a private `Root CA`, `Intermediate CA` and issuing server or client (mutual TLS) certificates.

It began as a C# port of the Go project https://github.com/jsha/minica using `GitHub Copilot`/`GPT5`. Did it really write all this code? Quite a large part enabling me to rapidly achieve a working prototype, and to build on top of it, learning as I went along. Kudos to the generative AI folks!

If you want *your* app to look professional in demos, with SSL and single sign-on (via client certificate authentication), look no further.

> It is intended for development, lab, CI, microservice, or internal environments where you control all participating hosts. It does NOT currently implement OCSP or CRLs. If you want CRL, add BouncyCastle.Crypto, then use X509V2CrlGenerator, add revoked entries, then sign.

The tool is cross-platform and works on Windows, Linux, and macOS.


_I am using it actively in my own projects (for both SSO, REST APIs and on premise web-server)._

---

## Key Features

- Automatic generation of Root CA + Intermediate CA certificates, with an optional random suffix for CA name to avoid collisions.
- Easy generation of server certificates: DNS SANs / IP SANs / wildcard names.
- Easy generation of client certificates: UPN (User Principal Name) + PKCS#12 (.p12) export.
- Support for both RSA (2048) or ECDSA (P‑384) key algorithms.
- Supports Org, Org unit, Country:
  - OU and Country are applied only to end‑entity (leaf) certificates.
  - Organisation (O) is included on CA and leaf certificates.
- Easy generation of full-chain bundle(s) including leaf (client/server) + intermediate CA + root CA (if no intermediate, just root).
- Variable length certificate expiry.
- Built-in verification of the generated certificates, with warnings for potential issues.
- Writes out a human-readable dump of the certificates, and a JSON summary of the generated certificate details for CI/automation.

---

## When To Use

Good for:
- Local development TLS (e.g. web-server certificates))
- Internal service-to-service mTLS, client auth mTLS (mutual TLS / 2-way SSL)
- CI pipelines needing ephemeral certificates
- Demos and prototypes

Not for:
- Public internet trust (use `Let's Encrypt` or a public CA such as `VeriSign`)
- Production PKI requiring revocation (no OCSP/CRL), unless you supplement it
- Hardware‑secured key storage needs (HSM/TPM)

---

## IMPORTANT SECURITY WARNING! 

### Don't forget .gitignore 

Please do NOT commit the private keys, or certificates, to source control.

Always add the following to your `.gitignore` :
```
# MiniCA generated files
**/*.crt
**/*.key
**/*.p12
```

Please note: The pattern `**/*.crt` hides all CRTs (even deliberately committed public test roots). Consider narrowing to /Tools/MiniCA/cert/*.crt (if you want to keep repo root clean).

```
/Tools/MiniCA/cert/*.crt
/Tools/MiniCA/key/*.key
```

Always keep private keys on a secure host (e.g. use filesystem ACLs). Only distribute the public certificates (minica.crt, minica-intermediate.crt etc.) as needed for trust.

---

## PEM vs. CRT

Both file extensions are base-64 with headers; it is just a naming convention difference:

- A `.pem` certificate is ASCII, with `-----BEGIN CERTIFICATE-----` headers. It's common for web servers, easy to read/edit.
- A `.crt` extension is often used interchangeably with `.pem` for certificates.

MiniCA creates a `.CRT`. If you need a `.PEM`, simply rename `*.CRT` to `*.PEM`.

---

## Build

From repository root (requires .NET 9 SDK):

```bash
dotnet build -c Release
```

Run the tool:
````bash
dotnet run -p MiniCA/ -c Release -- --help
````

Or publish a single executable:
````bash
dotnet publish -p:PublishSingleFile=true -c Release -o ./output
````

---

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--ca-filename` | Root filename _without_ extension | `minica` |
| `--key-path <path>` | Path for all private keys | `.\key\` |
| `--cert-path <path>` | Path for all certificates | `.\cert\` |
| `--ca-name <name>` | Root CA Common Name (without "Root CA" suffix)| `Test` (="Test Root CA") |
| `--ca-alg <rsa|ecdsa>` | Algorithm for new key pairs | `ecdsa` |
| `--ca-expiry <time>` | Root CA validity period `999[y|m|d]` | `20y` |
| `--intermediate-expiry <time>` | Intermediate CA validity period `999[y|m|d]` | `10y` |
| `--leaf-expiry <time>` | Leaf certificate validity period `999[y|m|d]` | `2y` |
| `--no-intermediate` | Do not create an intermediate CA, sign leaf certs directly from the root CA (not recommended) | false |
| `--domains <d1,d2>` | Comma-separated DNS names for SAN | (none) |
| `--ip-addresses <i1,i2>` | Comma-separated IP SAN entries | (none) |
| `--user <upn>` | UPN for client certificate (enables client mode) | (none) |
| `--p12-password <pwd>` | Password for generated .p12 (client mode) | `letmein` |
| `--organisation <org>` | O= value (<=64 chars allowed) | (none) |
| `--organisational-unit <ou>` | OU= value (<=64 chars allowed)| (none) |
| `--country <CC>` | C= 2-letter ISO code | (none) |
| `--suffix-random` | Append short random hex to CA name | off |
| `--add-client-eku-to-server-cert` | Add the Client Authentication EKU to server certificates (some clients need this). Comply with best practice by leaving it "off" unless you have a genuine reason. | off |
| `-h`, `--help` | Show usage | – |

At least one of: `--domains`, `--ip-addresses`, or `--user` must be supplied.

### Exit Codes

- `0` success
- `1` validation or unexpected error. `Console.Error` contains the error message.
- `2` warning - one or more generated certificate(s) flagged possible issues during verification.

Console output includes a clear echo of args at start.

Although what it does should be fairly obvious, for peace of mind it writes out a `.txt` file containing an independent summary of the generated certificate, including serial number, subject, issuer, SANs, validity period etc. This might be useful for troubleshooting.

---

## Separation of Keys and Certificates

By default, all keys and certificates are created in the exe directory in folders `./key/` and `./cert/`. You can change this with the `--key-path` and `--cert-path` options:
```bash
MiniCA.exe --key-path c:\productx\keys --cert-path c:\productx\certs --domains myintra.net --ip-addresses 127.0.0.1
```

With the exception of the default, don't forget to create the directories first, as MiniCA does not create them for you. This is by design, because it is important you manage them properly, and that starts with considering security.

- If you see `[ERROR] Error: The private key file-path does not exist.`, ensure the specified `--key-path` directory exists and is writable.

- If you see `[ERROR] Error: The certificate file-path does not exist.`, ensure the specified `--cert-path` directory exists and is writable.

---

## Quick Start (Server Certificate)

If you want to spin up an internal web-server with TLS/SSL, you will need a server certificate. 

Let's say your web site is `myintra.net`. Simply generate a root & intermediate CA and a server cert for myintra.net and 127.0.0.1 like this:
```bash
MiniCA.exe --domains myintra.net --ip-addresses 127.0.0.1
```

This creates the following files: 
- `minica.key`, `minica.crt` : Root CA key and certificate
- `minica-intermediate.key`, `minica-intermediate.crt` : Intermediate CA key and certificate
- `myintra.net.key`, `myintra.net.crt` : Server key and certificate (signed by the intermediate CA, or root CA if no intermediate)
- `myintra.net.fullchain.key`, `myintra.net.fullchain.crt` : full chain
- `README.txt` : Info about how to install the generated certs in Windows using CertUtil

Add the certificate to the web-server, and import the root and intermediate CA certificates into your OS/browser trust store, so it will trust the server certificate.
 
---

## Wildcard Server Certificate Example

It's common to use a wildcard certificate for internal domains, e.g. `*.example.internal`. The overall principle doesn't change just because of the "*".
`www.example.internal`, `ftp.example.internal` would both match this wildcard.

You generate a root & intermediate CA and a server cert for a wildcard domain in the same way:
```bash
MiniCA.exe --domains "*.example.internal" --ip-addresses 192.168.1.100
```

This creates the following files: 
- `minica.key`, `minica.crt` : Root CA key and certificate
- `minica-intermediate.key`, `minica-intermediate.crt` : Intermediate CA key and certificate
- `wildcard.example.internal.key`, `wildcard.example.internal.crt` : Server key and certificate (signed by the intermediate CA, or root CA if no intermediate)
- `wildcard.example.fullchain.key`, `wildcard.example.fullchain.crt` : full chain

Any `*` replaced by `wildcard`, due to most operating systems reserving it.

So, what happens if we call it with multiple domains, including a wildcard?

```bash
MiniCA.exe --domains "*.example.internal,localhost,*.dev-demo.com" --ip-addresses 192.168.1.100
```

Whilst it looks a bit odd, it is valid to have multiple SAN entries. The first domain is used for the file prefix.

---

## IP-only Example

It's possible that you want a secure connection to a server that is only known by its IP address. You can do that with certificates on both ends.

For that you generate a root & intermediate CA then a server certificate for the IP addresses like this:
```bash
MiniCA.exe --ip-addresses 192.168.1.100
```

This creates the following files:
- `minica.key`, `minica.crt` : Root CA key and certificate
- `minica-intermediate.key`, `minica-intermediate.crt` : Intermediate CA key and certificate
- `192.168.1.100.key`, `192.168.1.100.crt` : Server key and certificate (signed by the intermediate CA)
- `192.168.1.100.fullchain.key`, `192.168.1.100.fullchain.crt` : Key + Certs combining server + Intermediate + Root CA (for server use)

---

## Making a short-lived certificate

If you want a server/user certificate that lasts only a short time, use the `--leaf-expiry` option. For example, to create a certificate that lasts only 7 days:

```bash
MiniCA.exe --domains myintra.net --ip-addresses 192.168.1.100 --leaf-expiry 7d
```

You can use `d` (days), `m` (months), or `y` (years). The maximum is `999y`.

This might be because you want to rotate certificates every day or week.

It is also possible to create a short-lived root CA or intermediate CA, but this is not recommended. The `--ca-expiry` and `--intermediate-expiry` options are available for that purpose.  

---

## Mutual TLS / 2-way SSL => Client Certificates

Or maybe like me, you want to use client certificate authentication for single sign-on to your internal web application (using mTLS / 2-way SSL)?

Let's say you have a web-server (e.g. `www.mysite.io`), and a user `dave@mysite.io` who needs a client certificate to access it.

For this you make the client certificate with the `--user` option (example user `dave@mysite.io`):

```bash
MiniCA.exe --user dave@mysite.io
```

The client certificate has a UPN SAN, you can map it to a user account in your application. The PKCS#12 file can be imported into browsers or OS keystores.

This creates the following files: 
- `minica.key`, `minica.crt` : Root CA key and certificate
- `minica-intermediate.key`, `minica-intermediate.crt` : Intermediate CA key and certificate
- `dave@mysite.io.key`, `dave@mysite.io.crt` : Client key and certificate (signed by the intermediate CA, or root CA if no intermediate CA)
- `dave@mysite.io.p12` : PKCS#12 archive for the client certificate, with the password `letmein` (use the `--p12-password` option to change)
- `dave@mysite.io.fullchain.key`, `dave@mysite.io.fullchain.crt` : full chain

You create a server certificate for your web-server (e.g. `www.mysite.io`) as well, as follows:
```bash 
MiniCA.exe --domains www.mysite.io,127.0.0.1
```

The Root CA and Intermediate CA certificates provide a trust relationship because the root signed the intermediate, and the intermediate signed the client certificate.

---

## Example nginx Server Certificate Usage

In the previous example, we created a server certificate for `www.mysite.io` and a client certificate for `dave@mysite.io`. Using nginx as a reverse proxy, we can configure it to use the server certificate, and optionally request a client certificate for authentication.

We set the paths to your generated certificates. The cert needs to be in CRT format, and be a full chain certificate. e.g. for `www.mysite.io` :
- `ssl_certificate /etc/ssl/certs/www.mysite.io.fullchain.crt;`
- `ssl_certificate_key /etc/ssl/private/www.mysite.io.fullchain.key;`

### Client certificate authentication settings

It needs to trust the CA that issued the client certificates, so we point it at the Root CA certificate. e.g. `minica.crt` :

- `ssl_client_certificate /etc/ssl/certs/minica.crt;` Use the CA certificate
- `ssl_trusted_certificate /etc/ssl/certs/minica.crt;` Use the CA certificate

If the user provides a certificate, it'll try SSO; if they don't provide a certificate, it'll just do normal auth (user/password, etc)

- `ssl_verify_client optional;`  Accept any client certificate optionally - cert => sso, no cert => login screen
- `ssl_verify_depth 2;`

In the server block, we ask the proxy to pass the client certificate info to the application:

- `proxy_set_header X-SSL-Client-Verify $ssl_client_verify;` SUCCESS, FAILED, NONE
- `proxy_set_header X-SSL-Client-DN $ssl_client_s_dn;` subject distinguished name of the client certificate
- `proxy_set_header X-SSL-Client-Serial $ssl_client_serial;`  serial number of the client certificate
- `proxy_set_header X-SSL-Client-I-DN $ssl_client_i_dn;` distinguished name of the issuer (CA)

If you're using Docker, don't forget to copy the files in to the image: (`www.mysite.io` used in the example)

```bash
# this certificate is the CA + the web-server certificate in one file
COPY config/nginx/www.mysite.io.fullchain.crt /etc/ssl/certs/www.mysite.io.fullchain.crt

# the key is for the web-server SSL certificate, not the root CA key
COPY config/nginx/www.mysite.io.fullchain.key /etc/ssl/private/www.mysite.io.fullchain.key

# ensure it trusts the CA, so the API is trusted
COPY config/nginx/www.mysite.io.fullchain.crt /etc/ssl/certs/www.mysite.io.fullchain.crt
COPY config/nginx/www.mysite.io.fullchain.key /etc/ssl/private/www.mysite.io.fullchain.key

# the CA cert and key for client certificate verification
COPY config/nginx/minica.crt /etc/ssl/certs/minica.crt


COPY config/nginx/minica.crt /tmp/minica.crt
COPY config/nginx/minica.key /tmp/minica.key
COPY config/nginx/www.mysite.io.fullchain.crt /tmp/www.mysite.io.fullchain.crt

# Install the CA certificate into the Java truststore and the API certificate
RUN keytool -import -trustcacerts -alias MySiteCA -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit -file /tmp/minica.crt -noprompt && \
	keytool -import -trustcacerts -alias www.mysite.io -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit -file /tmp/www.mysite.io.fullchain.crt -noprompt && \
	rm /tmp/minica.crt /tmp/minica.key /tmp/www.mysite.io.fullchain.crt
```

_Adjust paths as needed._

Maybe an example will help, so here's what I do in Lucee (see: lucee.org). Lucee has nginx as a proxy providing SSL.

If the client certificate is offered by the browser , then we expect these headers to be present:
- `x-ssl-client-dn`	     string	C=UK,O=MySite Ltd,OU=MySite User,`CN=dave@mysite.io`
- `x-ssl-client-i-dn`	 string	O=MySite Ltd,CN=MySite Intermediate CA
- `x-ssl-client-serial`	 string	1366DC588E11ED5989B53BF39DC38C90
- `x-ssl-client-verify`	 string	`SUCCESS` <- not FAILED / NONE

We can use this information to do single sign-on (SSO) into our application.

```bash
requestData = getHttpRequestData();

if( structKeyExists(requestData, "headers" ) and 
	structKeyExists(requestData.headers, "X-SSL-Client-Verify") )
{
	// we have a header, is the certificate valid?
	switch( requestData.headers["X-SSL-Client-Verify"] )
	{
		case "SUCCESS":
			include template="/sso-auth-from-cert.cfm";
			break;

		case "FAILED":
			// certificate is not valid we send them to a page asking them to contact support
			location(url="/error-pages/cant-signon.cfm", addtoken="false");
			break;

		case "NONE":
			//  no client cert presented, so we continue to the login page
			break;

		default:
			// fallback to login page
			break;
	}
}
```

We follow this logic:
- if it receives a client certificate (indicated by the presence of the `X-SSL-Client-Verify` header = `SUCCESS`), it tries the SSO authentication route.
- if the certificate is _invalid_, it send them to an error page where it shows certificate details and ask them to contact support.
- if no certificate is presented, it shows the normal login page.

The art is in what you do with the first option; how you map the certificate to a user account...

It should verify a number of details in the certificate, including the "issuer" (CA) and ends with extracting the email address from the `CN=` field of the subject DN.

e.g. The subject DN looks like this:
`C=UK,O=MySite Ltd,OU=MySite User,CN=dave@mysite.io`

It parses the `CN=` and extracts `dave@mysite.io`, and perform basic sanity validation.
It uses a REST API with mechanisms in place to assert identity.

#### This is a fairly well known pattern, which has been used for many years in various systems. It works well for internal applications where you can control the issuance of client certificates.

---

## Example Output (Client Certificate)

Here's an example of generating a client certificate for user `dave@example.com`, providing many of the arguments:
```bash
MiniCA.exe --user dave@example.com --ca-name "Lab Root CA" --p12-password StrongP@ssw0rd --organisation "Example Ltd" --organisational-unit Engineering --country GB --ca-filename XYZ --key-path c:\temp\key --cert-path c:\temp\cert
```

Output would be as follows:
```bash
   _____  .__       .___________     _____
  /     \ |__| ____ |__\_   ___ \   /  _  \
 /  \ /  \|  |/    \|  /    \  \/  /  /_\  \     MiniCA - A simple Certificate Authority tool
/    Y    \  |   |  \  \     \____/    |    \    Based on https://github.com/jsha/minica (GoLang)
\____|__  /__|___|  /__|\______  /\____|__  /
        \/        \/           \/         \/

Arguments:
--user dave@example.com --ca-name "Lab Root CA" --p12-password StrongP@ssw0rd --organisation "Example Ltd" --organisational-unit Engineering --country GB --ca-filename XYZ --key-path c:\temp\key --cert-path c:\temp\cert

Generation Options:
  ROOT CA
    Name:              Lab
    Key Filename:      c:\temp\key\XYZ.key
    Cert Filename:     c:\temp\cert\XYZ.crt
    Algorithm:         ecdsa
    Expiry:            20y
  INTERMEDIATE CA
    Key Filename:      c:\temp\key\XYZ-intermediate.key
    Cert Filename:     c:\temp\cert\XYZ-intermediate.crt
    Expiry:            10y
  CLIENT AUTH
    User:              dave@example.com
    P12 Password:      StrongP@ssw0rd
    P12 FilePath:      c:\temp\cert\dave@example.com.p12
    Expiry:            2y
  Organisation:        Example Ltd
  Organisational Unit: Engineering
  Country:             GB
  Random Suffix:       no

Generated  Root CA  certificate:
 -  SERIAL #      02472285bac4bec4
 -  CERTIFICATE   c:\temp\cert\XYZ.crt
 -  PRIVATE KEY   c:\temp\key\XYZ.key

Generated  Intermediate CA  certificate:
 -  SERIAL #      771a729526b9fffb2eda9fa368b9cf7b
 -  CERTIFICATE   c:\temp\cert\XYZ-intermediate.crt
 -  PRIVATE KEY   c:\temp\key\XYZ-intermediate.key

Signing with the  Intermediate CA  certificate

 dave@example.com
 -  SERIAL #      266FC5DA989A7CA960B172961F33D70D
 -  CERTIFICATE   c:\temp\cert\dave@example.com.crt
 -  PRIVATE KEY   c:\temp\key\dave@example.com.key
 -  CHAIN CERT    c:\temp\cert\dave@example.com.fullchain.crt
 -  CHAIN KEY     c:\temp\key\dave@example.com.fullchain.key


This is a  CLIENT  certificate.

Success
```

_Please don't place `.key` and `.cert` in the temp folder! This is an example of output._

The UPN is placed in SAN as `otherName / UPN` (via `AddUserPrincipalName`).

It writes keys to `c:\temp\key\` containing:
- `XYZ.key` - the Root CA key
- `XYZ-intermediate.key` - the Intermediate CA key
- `dave@example.com.key` - the client key
- `dave@example.com.fullchain.key` - identical to the leaf private key; provided only for naming symmetry.

And writes certificates to `c:\temp\cert\` containing:
- `XYZ.crt` - the Root CA certificate
- `XYZ-intermediate.crt` - the Intermediate CA certificate
- `dave@example.com.crt` - the client certificate
- `dave@example.com.p12` - a PKCS#12 for importing into browser / OS key stores
- `dave@example.com.fullchain.crt` - full chain
- `README.txt` - instructions for installing the certs in Windows

In addition it writes out a `dave@example.com.json` containing the certificate details in JSON format, which may be useful for troubleshooting, or automation.
```
{
  "Generation": {
    "Tool": "MiniCA",
    "Version": "1.0.0.0",
    "When": "2025-09-15T21:14:44.9841673\u002B00:00",
    "GeneratedRootCA": true,
    "GeneratedIntermediateCA": true,
    "GeneratedLeafCert": true,
    "Success": true
  },
  "CommonName": "dave@example.com",
  "Domains": [],
  "IPAddresses": [],
  "Type": "client",
  "User": "dave@example.com",
  "Organisation": "Example Ltd",
  "OrganisationalUnit": "Engineering",
  "Country": "GB",
  "NotBefore": "2025-09-15T22:14:44+01:00",
  "NotAfter": "2027-09-15T22:14:44+01:00",
  "SerialNumber": "0dd7331f9672b160a97c9a98dac56f26",
  "Thumbprint": "fe97d3f1b2de970136f21c0687e5fd69bb6ed782",
  "CertificateFilePath": "c:\\temp\\cert\\dave@example.com.crt",
  "PrivateKeyFilePath": "c:\\temp\\key\\dave@example.com.key",
  "FullChainCertificateFilePath": "c:\\temp\\cert\\dave@example.com.fullchain.crt",
  "FullChainPrivateKeyFilePath": "c:\\temp\\key\\dave@example.com.fullchain.key",
  "Expiry": "2y",
  "Issuer": {
    "Subject": "O=Example Ltd, CN=Lab Intermediate CA",
    "SerialNumber": "7bcfb968a39fda2efbffb92695721a77",
    "Thumbprint": "3406e7b826149fd6ed5f69faa6b203c91504568b",
    "NotBefore": "2025-09-15T22:14:44+01:00",
    "NotAfter": "2035-09-13T22:14:44+01:00",
    "CertificateFilePath": "c:\\temp\\cert\\XYZ-intermediate.crt",
    "PrivateKeyFilePath": "c:\\temp\\key\\XYZ-intermediate.key",
    "Expiry": "10y"
  },
  "Root": {
    "Subject": "CN=Lab Root CA",
    "SuffixRandomExtensionToCAName": false,
    "RootCACertificateFilePath": "c:\\temp\\cert\\XYZ.crt",
    "RootCAPrivateKeyFilePath": "c:\\temp\\key\\XYZ.key",
    "CaAlg": "ecdsa",
    "Expiry": "20y"
  }
}
```
#### Using that JSON you can call MiniCA.exe, and afterwards, check the `.json` file to determine what happened. For example if `Success` is not `true`, it might be a good idea to stop your process.

Lastly, it writes a dump of the certificates (full and regular) to the `--cert-path` containing the certificate details in human-readable format, which may be also be useful for troubleshooting.

```
3 certificates (chain) in file: c:\temp\cert\dave@example.com.fullchain.crt

CERTIFICATE #1
  [This is an end-entity certificate]
  Subject:              C=GB, O=Example Ltd, OU=Engineering, CN=dave@example.com
  Issuer:               Lab Intermediate CA
  Valid From (Local):   2025-09-15 22:14:44Z 
  Valid To   (Local):   2027-09-15 22:14:44Z 
  Valid From (UTC):     2025-09-15 21:14:44Z
  Valid To   (UTC):     2027-09-15 21:14:44Z
  Thumbprint:           fe97d3f1b2de970136f21c0687e5fd69bb6ed782
  Serial Number:        266fc5da989a7ca960b172961f33d70d
  Signature Algorithm:  sha256ECDSA (OID 1.2.840.10045.4.3.2)
  Public Key Algorithm: ECC P-384 (OID 1.2.840.10045.2.1)
  Enhanced Key Usages:
    - Client Authentication (1.3.6.1.5.5.7.3.2)
  Key Usages:
    - Digital Signature
  Subject Alternative Names:
    - RFC822 Name=dave@example.com
    - Other Name:
     Principal Name=dave@example.com
  Basic Constraints:    Certificate Authority: No, Path Length Constraint: N/A, Critical: No
  Notes:
    This certificate can be used for client authentication, but not for server authentication.

CERTIFICATE #2
  [This is an INTERMEDIATE CA certificate]
  Subject:              O=Example Ltd, CN=Lab Intermediate CA
  Issuer:               Lab Root CA
  Valid From (Local):   2025-09-15 22:14:44Z 
  Valid To   (Local):   2035-09-13 22:14:44Z 
  Valid From (UTC):     2025-09-15 21:14:44Z
  Valid To   (UTC):     2035-09-13 21:14:44Z
  Thumbprint:           3406e7b826149fd6ed5f69faa6b203c91504568b
  Serial Number:        771a729526b9fffb2eda9fa368b9cf7b
  Signature Algorithm:  sha256ECDSA (OID 1.2.840.10045.4.3.2)
  Public Key Algorithm: ECC P-384 (OID 1.2.840.10045.2.1)
  Enhanced Key Usages:
    - Server Authentication (1.3.6.1.5.5.7.3.1)
    - Client Authentication (1.3.6.1.5.5.7.3.2)
  Key Usages:
    - Certificate Signing
    - CRL Signing
  Basic Constraints:    Certificate Authority: Yes, Path Length Constraint: 0, Critical: Yes
  Notes:
    This CA certificate cannot issue CA certificates, but can issue server/client certificates.
    This certificate can be used for both server and client authentication.

CERTIFICATE #3
  [This is a ROOT CA certificate]
  Subject:              O=Example Ltd, CN=Lab Root CA
  Issuer:               Self-signed
  Valid From (Local):   2025-09-15 22:14:44Z 
  Valid To   (Local):   2045-09-10 22:14:44Z 
  Valid From (UTC):     2025-09-15 21:14:44Z
  Valid To   (UTC):     2045-09-10 21:14:44Z
  Thumbprint:           76fa079f006813ad0f8dbcaf3196fa73a930d047
  Serial Number:        02472285bac4bec4
  Signature Algorithm:  sha256ECDSA (OID 1.2.840.10045.4.3.2)
  Public Key Algorithm: ECC P-384 (OID 1.2.840.10045.2.1)
  Key Usages:
    - Certificate Signing
    - CRL Signing
  Basic Constraints:    Certificate Authority: Yes, Path Length Constraint: 1, Critical: Yes
  Notes:
    This CA certificate can issue other CA certificates, but only up to a depth of 1.
    No Enhanced Key Usages (EKUs) specified. This means the certificate can be used for any purpose.

============================
CERTIFICATE CHAIN VALIDATION
============================

  Leaf #1: dave@example.com
    With AllowUnknownCertificateAuthority: Success
      [0] Subject=dave@example.com; Issuer=Lab Intermediate CA; Status=OK
      [1] Subject=Lab Intermediate CA; Issuer=Lab Root CA; Status=OK
      [2] Subject=Lab Root CA; Issuer=Lab Root CA; Status=OK
    Strict (NoFlag): Success
      [0] Subject=dave@example.com; Issuer=Lab Intermediate CA; Status=OK
      [1] Subject=Lab Intermediate CA; Issuer=Lab Root CA; Status=OK
      [2] Subject=Lab Root CA; Issuer=Lab Root CA; Status=OK
```

You might want to inspect the certificates without importing them into a store. OpenSSL is a common tool, but it doesn't make it that easy. 
If any issues are discovered it will report them, and exit with code `2`.

This might seem strange. Why check the certificates you just created? Because it is incredibly frustrating applying certificates only to find out they are invalid. I prefer to be 100% sure, so incorporated this nice little tool to provide that peace of mind.

---

## Using RSA Instead of ECDSA

By default MiniCA generates ECDSA (P-384) keys. This is generally preferred for performance and security, but some legacy systems may require RSA keys.

You can generate certificates with RSA keys instead of the default ECDSA keys, by specifying the `--ca-alg rsa` option.

For example, to create a root & intermediate CA and a server cert for `localhost` with RSA keys:
```bash
MiniCA.exe --domains www.example.com --ca-alg rsa
```

This creates the usual files, except the keys will be RSA (2048 bits) instead of ECDSA (P-384).

> The restriction is that all keys (root, intermediate, leaf) will be RSA if you choose RSA (same for ECDSA). You cannot mix algorithms in this version. I know how, but haven't had time or need to support it.

---

## Skipping an Intermediate CA

By default MiniCA creates a root CA and an intermediate CA, and signs leaf certificates with the intermediate CA. This is the recommended security best practice.

If you want to skip the intermediate CA and have the root CA sign leaf certificates directly, use the `--no-intermediate` option.

For example, to create a root CA and a server cert for `localhost` without an intermediate CA:
```bash
MiniCA.exe --domains localhost --no-intermediate
```

This creates the following files:
- `minica.key`, `minica.crt` : Root CA key and certificate
- `localhost.key`, `localhost.crt` : Server key and certificate (signed by the root CA)
- `localhost.fullchain.key`, `localhost.fullchain.crt` : full chain
- `README.txt` : Info about how to install the generated certs in Windows using CertUtil
- `localhost.json` : JSON details of the generated certificate
- `localhost.txt` : Human-readable details of the generated certificate
- `minica.json` : JSON details of the certificate

---

## File Overwrite Policy

MiniCA _never_ overwrites existing files, preserving any previously issued certificates and keys.
- Root / Intermediate key or cert
- Leaf certs / keys

#### You can delete the file(s) to force regeneration, at a cost...

To restart from scratch (use inside certificate folder):
```bash
rm -f key/*
rm -f crt/*
```

This "no overwrite" policy prevents accidental loss of previously issued identities. You ideally do not want to replace the Root CA or intermediate CA, as without revocation you'll have 2 live certificates for the same domain.
Of course you can do what I do, which is remove the certificates (e.g. delete them from the certificate store).

For example after modifying MiniCA, I delete them and regenerate everything from scratch.

Regeneration requires deleting both minica*.key and minica*.crt pairs.

Just be mindful that if you delete the root or intermediate CA files, any previously issued certificates will no longer be trusted unless you re-import the new root/intermediate CA certs.

---

## Security Notes

- Protect `minica.key` (root) & `minica-intermediate.key` (intermediate) – treat as secrets.
- There is currently *no* revocation mechanism: if a key is compromised, you must redistribute a new trust anchor. Maybe I will add one, if there is enough interest.
- Rotate keys periodically for long-lived CAs.
- ECDSA (P-384) is default: smaller & faster handshakes; choose RSA if compatibility needed with legacy systems.
- SHA-256 is used for signatures; serial numbers are 128-bit random positive values.
- Don’t distribute private root or intermediate keys.

---

## Client PKCS#12 Import

The generated `.p12` file can be imported into browsers or OS keystores for client authentication.

- Browser (Chrome/Edge/Firefox on Windows): double-click `.p12`, follow import wizard (user store, personal).
- macOS: double-click `.p12`, Keychain Access; ensure identity trusted.
- Linux: import into browser or `p11-kit` as needed.

---

## Example Combined Script (Linux)

```bash
#!/bin/bash
# Generate new certificates
dotnet run --project Tools/MiniCA -- --user demo_user
dotnet run --project Tools/MiniCA -- --ca-name "Sandbox Root CA" --domains api.sandbox.local,auth.sandbox.local --organisation "Sandbox Org" --organisational-unit "Platform" --country US
sudo cp certs/minica.crt /usr/local/share/ca-certificates/minica.crt 
sudo update-ca-certificates
```

---

## Adding To Trust / Certificate Store

### Windows Certificate Store

Using PowerShell...

- To add the Root CA to the Windows Trusted Root Certification Authorities store:
```powershell
Import-Certificate -FilePath .\minica.crt -CertStoreLocation Cert:\LocalMachine\Root
```

- To add the Intermediate CA to the Windows Intermediate Certification Authorities store:
```powershell
Import-Certificate -FilePath .\minica-intermediate.crt -CertStoreLocation Cert:\LocalMachine\CA
```

- To add a client certificate to the Personal store:
```powershell
Import-PfxCertificate -FilePath .\demo_user.p12 -CertStoreLocation Cert:\CurrentUser\My -Password (ConvertTo-SecureString -String "letmein" -AsPlainText -Force)
```

- To add a server certificate to the Personal store:
```powershell
Import-Certificate -FilePath .\myintra.net.crt -CertStoreLocation Cert:\LocalMachine\My
```

- To view certificates in the store:
```powershell
Get-ChildItem -Path Cert:\LocalMachine\Root
Get-ChildItem -Path Cert:\LocalMachine\CA
Get-ChildItem -Path Cert:\CurrentUser\My
Get-ChildItem -Path Cert:\LocalMachine\My
```

### Linux system trust store

To add the Root CA to the system trust store (Debian/Ubuntu):

```bash
sudo cp certs/minica.crt /usr/local/share/ca-certificates/minica.crt
sudo update-ca-certificates
```

### macOS Keychain

To add the Root CA to the System keychain:
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./minica.crt
```
To add the Intermediate CA to the System keychain:
```bash
sudo security add-trusted-cert -d -r trustAsRoot -k /Library/Keychains/System.keychain ./minica-intermediate.crt
```
To add a client certificate to the login keychain:
```bash
security import ./demo_user.p12 -k ~/Library/Keychains/login.keychain-db -P letmein -T /usr/bin/security
```
To add a server certificate to the System keychain:
```bash
sudo security add-trusted-cert -d -r trustAsRoot -k /Library/Keychains/System.keychain ./myintra.net.crt
```

---

## Mini CI Example

Here's an example GitHub Actions workflow to generate certificates using MiniCA and store them as artifacts.

```yaml
name: Generate Certificates
on:
  push:
    branches:
      - main
  workflow_dispatch:

  jobs:
  generate-certs:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      - name: Set up .NET
        uses: actions/setup-dotnet@v3
        with:
          dotnet-version: '7.0.x'
      - name: Build MiniCA
        run: dotnet build Tools/MiniCA -c Release
      - name: Generate Root and Intermediate CA
        run: dotnet run --project Tools/MiniCA -- --ca-name "GitHub Actions Root CA" --ca-filename gha-root --organisation "My Org" --organisational-unit "DevOps" --country US
      - name: Generate Server Certificate
        run: dotnet run --project Tools/MiniCA -- --domains api.example.com,auth.example.com --ca-name "GitHub Actions Root CA" --organisation "My Org" --organisational-unit "DevOps" --country US
      - name: Generate Client Certificate
        run: dotnet run --project Tools/MiniCA -- --user demo_user
      - name: Upload Certificates as Artifacts
      uses: actions/upload-artifact@v3
        with:
          name: certificates
          path: certs/
          retention-days: 7
          - name: Upload Keys as Artifacts
          uses: actions/upload-artifact@v3
          with:
            name: keys
            path: certs/
            retention-days: 7
            - name: List Generated Files
            run: ls -l certs/
```

Or using a script, that you can call from your CI/CD pipeline that checks the .json file for success:

```bash
#!/bin/bash
set -e
dotnet run --project Tools/MiniCA -- --user demo_user
if [ $? -ne 0 ]; then
  echo "MiniCA failed to generate the certificate"
  exit 1
fi
if ! grep -q '"Success": true' certs/demo_user.json; then
  echo "Certificate generation was not successful"
  exit 1
fi
echo "Certificate generated successfully"
```

---

## Troubleshooting

| Issue | Resolution |
|-------|------------|
| Browser not trusting cert | Ensure root & intermediate CA's are installed into correct trust store |
| Server wants full chain | Use `<cn>.fullchain.crt` |
| Regenerate CA | Delete `minica*` root / intermediate files first |
| Client auth failing | Confirm UPN SAN present (inspect cert) |

MiniCA outputs a `.txt` file per leaf certificate and full-chain to help prove it is correct. 
It's of the same name (with a different extension) to the certificate. Look at that if you are unsure what is going on, in particular the full-chain.

Other issues:

- If you receive a `permission denied` error, ensure the output directory is writable.
- For .NET related errors, ensure you have the correct version of the .NET SDK installed.

---

## Acknowledgements

- Thanks to the author of the original Go minica project.

- A big THANK YOU to `GitHub Copilot` / `GPT5` for patience and amazing feedback. The attention to detail blows my mind. 

_If you haven't asked GPT5 et al to review your README and ensure alignment with code, try it. I am staggered by what it spotted that I had missed!_

---

## License & Attribution

MIT License. See [LICENSE](LICENSE) file.

Original Go MiniCA: MIT (https://github.com/jsha/minica)  

This C# port and enhancements retain MIT for original portions; new code is provided under the same permissive intent.  

Please give credit upstream (star the original project) if you find this useful.

---

## Disclaimer

Use for development / internal testing / deployment. It's great for learning and prototyping TLS/mTLS setups. It works for micro-services, and proof of concepts.

It is _not_ a replacement for a production-grade PKI or public CA.

---

_Happy hacking & secure experimenting!_