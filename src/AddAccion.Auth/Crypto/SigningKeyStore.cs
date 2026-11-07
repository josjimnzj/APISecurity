using System.Security.Cryptography;
using System.Text.Json;
using AddAccion.Auth.Configuration;
using AddAccion.Auth.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AddAccion.Auth.Crypto;

public sealed record SigningKey(string KeyId, string Algorithm, SecurityKey PrivateKey, JsonWebKey PublicJwk);

/// <summary>
/// Loads the signing keys once at startup from PEM files (mounted secret). The key id is the
/// RFC 7638 JWK thumbprint, so any implementation (e.g. a future Go service) derives the same kid
/// from the same file. All loaded keys are published in the JWKS; only the active one signs.
/// </summary>
public sealed class SigningKeyStore
{
    public SigningKey Active { get; }
    public IReadOnlyList<SigningKey> All { get; }
    public IReadOnlyList<SecurityKey> ValidationKeys { get; }
    public IReadOnlyList<string> Algorithms { get; }
    public SigningCredentials ActiveCredentials { get; }

    /// <summary>Pre-serialized JWKS document (served as-is).</summary>
    public byte[] JwksJson { get; }

    public SigningKeyStore(IOptions<AuthServerOptions> options, IHostEnvironment environment, ILogger<SigningKeyStore> logger)
        : this(LoadKeys(options.Value.SigningKeys, environment, logger, out var activeIndex), activeIndex)
    {
    }

    internal SigningKeyStore(IReadOnlyList<SigningKey> keys, int activeIndex)
    {
        All = keys;
        Active = keys[activeIndex];
        ValidationKeys = keys.Select(k => (SecurityKey)k.PublicJwk).ToArray();
        Algorithms = keys.Select(k => k.Algorithm).Distinct(StringComparer.Ordinal).ToArray();
        ActiveCredentials = new SigningCredentials(Active.PrivateKey, Active.Algorithm);
        JwksJson = BuildJwks(keys);
    }

    private static List<SigningKey> LoadKeys(SigningKeyOptions options, IHostEnvironment environment, ILogger logger, out int activeIndex)
    {
        var keys = new List<SigningKey>();
        activeIndex = 0;

        if (string.IsNullOrWhiteSpace(options.Path))
        {
            if (!(environment.IsDevelopment() && options.AllowEphemeralDevelopmentKey))
                throw new InvalidOperationException("Auth:SigningKeys:Path is not configured.");
            Log.EphemeralSigningKey(logger);
            keys.Add(FromAlgorithm(RSA.Create(2048)));
            return keys;
        }

        if (!Directory.Exists(options.Path))
            throw new InvalidOperationException($"Signing key directory '{options.Path}' does not exist.");

        var files = Directory.GetFiles(options.Path, "*.pem").Order(StringComparer.Ordinal).ToArray();
        if (files.Length == 0)
            throw new InvalidOperationException($"No *.pem signing keys found in '{options.Path}'.");

        string? activeFile = options.ActiveKey;
        if (string.IsNullOrWhiteSpace(activeFile))
        {
            if (files.Length > 1)
                throw new InvalidOperationException("Several signing keys found: set Auth:SigningKeys:ActiveKey to the file name of the signing key.");
            activeFile = Path.GetFileName(files[0]);
        }

        activeIndex = -1;
        foreach (var file in files)
        {
            var key = FromPem(File.ReadAllText(file), file);
            if (string.Equals(Path.GetFileName(file), activeFile, StringComparison.Ordinal)) activeIndex = keys.Count;
            keys.Add(key);
            Log.SigningKeyLoaded(logger, file, key.KeyId, key.Algorithm);
        }

        if (activeIndex < 0)
            throw new InvalidOperationException($"Active signing key '{activeFile}' not found in '{options.Path}'.");
        if (keys.Select(k => k.KeyId).Distinct(StringComparer.Ordinal).Count() != keys.Count)
            throw new InvalidOperationException("Duplicate signing keys (same thumbprint) found.");
        return keys;
    }

    public static SigningKey FromPem(string pem, string source = "pem")
    {
        if (pem.Contains("ENCRYPTED", StringComparison.Ordinal))
            throw new InvalidOperationException($"{source}: encrypted PEM is not supported; protect the key with the secret store instead.");

        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportFromPem(pem);
            return FromAlgorithm(ecdsa);
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException)
        {
            ecdsa.Dispose();
        }

        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(pem);
            return FromAlgorithm(rsa);
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException)
        {
            rsa.Dispose();
        }

        throw new InvalidOperationException($"{source}: not an RSA or EC private key in PEM format.");
    }

    public static SigningKey FromAlgorithm(AsymmetricAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case RSA rsa:
            {
                if (rsa.KeySize < 2048) throw new InvalidOperationException("RSA signing keys must be at least 2048 bits.");
                var publicJwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(rsa.ExportParameters(false)));
                var kid = Base64UrlEncoder.Encode(publicJwk.ComputeJwkThumbprint());
                publicJwk.KeyId = kid;
                publicJwk.Use = "sig";
                publicJwk.Alg = SecurityAlgorithms.RsaSha256;
                return new SigningKey(kid, SecurityAlgorithms.RsaSha256, new RsaSecurityKey(rsa) { KeyId = kid }, publicJwk);
            }
            case ECDsa ecdsa:
            {
                var alg = ecdsa.KeySize switch
                {
                    256 => SecurityAlgorithms.EcdsaSha256,
                    384 => SecurityAlgorithms.EcdsaSha384,
                    521 => SecurityAlgorithms.EcdsaSha512,
                    _ => throw new InvalidOperationException("EC signing keys must use P-256, P-384 or P-521."),
                };
                var publicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(ECDsa.Create(ecdsa.ExportParameters(false))));
                var kid = Base64UrlEncoder.Encode(publicJwk.ComputeJwkThumbprint());
                publicJwk.KeyId = kid;
                publicJwk.Use = "sig";
                publicJwk.Alg = alg;
                return new SigningKey(kid, alg, new ECDsaSecurityKey(ecdsa) { KeyId = kid }, publicJwk);
            }
            default:
                throw new InvalidOperationException("Unsupported key type.");
        }
    }

    private static byte[] BuildJwks(IReadOnlyList<SigningKey> keys)
    {
        using var stream = new MemoryStream();
        using (var w = new Utf8JsonWriter(stream))
        {
            w.WriteStartObject();
            w.WriteStartArray("keys");
            foreach (var k in keys)
            {
                var j = k.PublicJwk;
                w.WriteStartObject();
                w.WriteString("kty", j.Kty);
                w.WriteString("use", j.Use);
                w.WriteString("alg", j.Alg);
                w.WriteString("kid", j.Kid);
                if (j.Kty == JsonWebAlgorithmsKeyTypes.RSA)
                {
                    w.WriteString("n", j.N);
                    w.WriteString("e", j.E);
                }
                else
                {
                    w.WriteString("crv", j.Crv);
                    w.WriteString("x", j.X);
                    w.WriteString("y", j.Y);
                }
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteEndObject();
        }
        return stream.ToArray();
    }

    /// <summary>Generates a new PKCS#8 PEM private key (used by the CLI "generate-key").</summary>
    public static string GeneratePem(string type)
    {
        AsymmetricAlgorithm key = type.ToUpperInvariant() switch
        {
            "RSA" => RSA.Create(3072),
            "EC" or "ES256" => ECDsa.Create(ECCurve.NamedCurves.nistP256),
            _ => throw new ArgumentException("type must be 'rsa' or 'ec'", nameof(type)),
        };
        using (key)
        {
            var pem = PemEncoding.Write("PRIVATE KEY", key.ExportPkcs8PrivateKey());
            return new string(pem) + "\n";
        }
    }
}
