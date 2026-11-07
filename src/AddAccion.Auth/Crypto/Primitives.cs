using System.Buffers.Binary;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using AddAccion.Auth.Configuration;
using Microsoft.Extensions.Options;

namespace AddAccion.Auth.Crypto;

/// <summary>CSPRNG-backed opaque values (codes, refresh tokens, jti, secrets).</summary>
public static class RandomTokens
{
    /// <summary>Base64url string of <paramref name="bytes"/> random bytes (32 bytes = 256 bits).</summary>
    public static string Create(int bytes = 32)
    {
        Span<byte> buffer = stackalloc byte[bytes];
        RandomNumberGenerator.Fill(buffer);
        return Base64Url.EncodeToString(buffer);
    }

    /// <summary>Client secrets carry a recognisable prefix so secret scanners (GitHub, GitLab, DLP) can flag leaks.</summary>
    public const string ClientSecretPrefix = "aasec_";

    public static string CreateClientSecret() => ClientSecretPrefix + Create(32);
}

/// <summary>
/// SHA-256 for high-entropy, server-generated values (client secrets, codes, refresh tokens).
/// A slow KDF is unnecessary for 256-bit random values and would make the token endpoint CPU bound.
/// </summary>
public static class TokenHasher
{
    public static byte[] Hash(string value)
    {
        var max = Encoding.UTF8.GetMaxByteCount(value.Length);
        var buffer = max <= 1024 ? stackalloc byte[max] : new byte[max];
        var written = Encoding.UTF8.GetBytes(value, buffer);
        return SHA256.HashData(buffer[..written]);
    }

    public static bool Matches(string presented, byte[] storedHash) =>
        storedHash.Length == 32 && CryptographicOperations.FixedTimeEquals(Hash(presented), storedHash);
}

/// <summary>RFC 7636 PKCE. Only S256 is accepted (plain is rejected per OAuth 2.1).</summary>
public static class Pkce
{
    public static bool IsValidVerifier(string? verifier)
    {
        if (verifier is null || verifier.Length is < 43 or > 128) return false;
        foreach (var c in verifier)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~')) return false;
        }
        return true;
    }

    /// <summary>S256 challenge is always 43 base64url chars (SHA-256 output).</summary>
    public static bool IsValidS256Challenge(string? challenge)
    {
        if (challenge is null || challenge.Length != 43) return false;
        foreach (var c in challenge)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')) return false;
        }
        return true;
    }

    public static string S256(string verifier)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.ASCII.GetBytes(verifier), hash);
        return Base64Url.EncodeToString(hash);
    }
}

public enum PasswordCheck
{
    Failed,
    Success,
    SuccessWeakHash,
}

/// <summary>Verifies stored password hashes. Replace in DI to support other legacy formats.</summary>
public interface IPasswordHashVerifier
{
    PasswordCheck Verify(string? storedHash, string password);

    /// <summary>Burns the same CPU as a real verification (user not found) to avoid user enumeration by timing.</summary>
    void VerifyDummy(string password);
}

/// <summary>
/// ASP.NET Core Identity formats: V3 (PBKDF2 HMAC-SHA1/256/512, any iteration count) and legacy V2
/// (PBKDF2-SHA1, 1000 iterations; accepted but reported as weak).
/// </summary>
public sealed class IdentityPasswordHashVerifier : IPasswordHashVerifier
{
    // PBKDF2-HMAC-SHA512, 100k iterations: the .NET 7+ Identity default. Random password, never matches.
    private const string DummyHash = "AQAAAAIAAYagAAAAEC8uerUEp3pILgWPT1/Gd6XzHHk3Ccsad7dZQ6vKTyUQtE0M2uY3rHhyZLaueNz70g==";
    private const int MaxIterations = 5_000_000;
    private const int MinIterationsNotWeak = 100_000;

    public PasswordCheck Verify(string? storedHash, string password)
    {
        if (string.IsNullOrEmpty(storedHash)) return PasswordCheck.Failed;
        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(storedHash);
        }
        catch (FormatException)
        {
            return PasswordCheck.Failed;
        }
        if (decoded.Length == 0) return PasswordCheck.Failed;

        return decoded[0] switch
        {
            0x00 => VerifyV2(decoded, password) ? PasswordCheck.SuccessWeakHash : PasswordCheck.Failed,
            0x01 => VerifyV3(decoded, password),
            _ => PasswordCheck.Failed,
        };
    }

    public void VerifyDummy(string password) => _ = Verify(DummyHash, password);

    private static bool VerifyV2(byte[] hash, string password)
    {
        const int saltSize = 16, subkeySize = 32;
        if (hash.Length != 1 + saltSize + subkeySize) return false;
        var salt = hash.AsSpan(1, saltSize);
        var expected = hash.AsSpan(1 + saltSize, subkeySize);
        Span<byte> actual = stackalloc byte[subkeySize];
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, actual, 1000, HashAlgorithmName.SHA1);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static PasswordCheck VerifyV3(byte[] hash, string password)
    {
        if (hash.Length < 13) return PasswordCheck.Failed;
        var prf = BinaryPrimitives.ReadUInt32BigEndian(hash.AsSpan(1, 4));
        var iterations = BinaryPrimitives.ReadUInt32BigEndian(hash.AsSpan(5, 4));
        var saltLength = BinaryPrimitives.ReadUInt32BigEndian(hash.AsSpan(9, 4));

        HashAlgorithmName algorithm;
        switch (prf)
        {
            case 0: algorithm = HashAlgorithmName.SHA1; break;
            case 1: algorithm = HashAlgorithmName.SHA256; break;
            case 2: algorithm = HashAlgorithmName.SHA512; break;
            default: return PasswordCheck.Failed;
        }

        if (iterations is 0 or > MaxIterations || saltLength < 16 || saltLength > 64) return PasswordCheck.Failed;
        var subkeyLength = hash.Length - 13 - (int)saltLength;
        if (subkeyLength < 16 || subkeyLength > 64) return PasswordCheck.Failed;

        var salt = hash.AsSpan(13, (int)saltLength);
        var expected = hash.AsSpan(13 + (int)saltLength, subkeyLength);
        Span<byte> actual = stackalloc byte[subkeyLength];
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, actual, (int)iterations, algorithm);
        if (!CryptographicOperations.FixedTimeEquals(actual, expected)) return PasswordCheck.Failed;

        return prf == 0 || iterations < MinIterationsNotWeak ? PasswordCheck.SuccessWeakHash : PasswordCheck.Success;
    }
}

/// <summary>Bounds concurrent PBKDF2 work so a login flood cannot starve the token endpoint of CPU.</summary>
public sealed class PasswordVerificationGate(IOptions<AuthServerOptions> options) : IDisposable
{
    private readonly SemaphoreSlim _semaphore = new(
        options.Value.Login.MaxConcurrentPasswordVerifications > 0 ? options.Value.Login.MaxConcurrentPasswordVerifications : Environment.ProcessorCount);

    public async Task<IDisposable?> TryEnterAsync(CancellationToken ct)
    {
        return await _semaphore.WaitAsync(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false) ? new Releaser(_semaphore) : null;
    }

    public void Dispose() => _semaphore.Dispose();

    private sealed class Releaser(SemaphoreSlim semaphore) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0) semaphore.Release();
        }
    }
}

/// <summary>
/// Signed double-submit cookie (OWASP CSRF cheat sheet): the form token is HMAC(key, cookie value),
/// so an attacker able to inject a cookie still cannot forge a matching form token.
/// The key is shared by all replicas through configuration.
/// </summary>
public sealed class CsrfProtector
{
    private readonly byte[] _key;

    public CsrfProtector(IOptions<AuthServerOptions> options)
    {
        var configured = options.Value.Login.CsrfKey;
        var ikm = string.IsNullOrWhiteSpace(configured) ? RandomNumberGenerator.GetBytes(32) : Convert.FromBase64String(configured);
        _key = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, salt: [], info: "addaccion-auth/login-csrf/v1"u8.ToArray());
    }

    public static string NewCookieValue() => RandomTokens.Create(32);

    public string TokenFor(string cookieValue)
    {
        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(cookieValue), mac);
        return Base64Url.EncodeToString(mac);
    }

    public bool Validate(string? cookieValue, string? formToken)
    {
        if (string.IsNullOrEmpty(cookieValue) || string.IsNullOrEmpty(formToken) || cookieValue.Length > 100 || formToken.Length > 100)
            return false;
        var expected = Encoding.ASCII.GetBytes(TokenFor(cookieValue));
        var actual = Encoding.ASCII.GetBytes(formToken);
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }
}
