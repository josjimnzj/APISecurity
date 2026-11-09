using System.Net;
using System.Text;
using AddAccion.Auth.Configuration;
using AddAccion.Auth.Crypto;
using AddAccion.Auth.Domain;
using AddAccion.Auth.Hosting;
using AddAccion.Auth.Persistence;
using AddAccion.Auth.Protocol;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AddAccion.Auth.Security;

public sealed record ClientAuthResult(ClientApplication? Client, string? Error, string? Description, bool UsedBasic, string? Method)
{
    public bool Succeeded => Client is not null && Error is null;

    public static ClientAuthResult Fail(string error, string description, bool basic = false) => new(null, error, description, basic, null);
}

/// <summary>
/// Token-endpoint client authentication (RFC 6749 §2.3, RFC 7523, OIDC Core §9):
/// client_secret_basic, client_secret_post, private_key_jwt and none (public clients).
/// Exactly one method per request; the method used must be the one registered for the client.
/// </summary>
public sealed class ClientAuthenticator(
    ClientCatalog clients,
    ClientAssertionValidator assertions,
    TimeProvider time,
    ILogger<ClientAuthenticator> logger)
{
    public const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    public async Task<ClientAuthResult> AuthenticateAsync(HttpContext ctx, RequestParameters p, string endpointUrl, CancellationToken ct)
    {
        var ip = ClientAddress.Resolve(ctx);
        var authorization = ctx.Request.Headers.Authorization;
        if (authorization.Count > 1)
            return ClientAuthResult.Fail(OAuthErrors.InvalidRequest, "Multiple Authorization headers.");

        string? basicId = null, basicSecret = null;
        var usedBasic = false;
        if (authorization.Count == 1 && authorization[0] is { } header && header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            usedBasic = true;
            if (!TryParseBasic(header.AsSpan(6).Trim(), out basicId, out basicSecret))
                return ClientAuthResult.Fail(OAuthErrors.InvalidClient, "Malformed Basic credentials.", basic: true);
        }

        var postSecret = p["client_secret"];
        var assertion = p["client_assertion"];
        var assertionType = p["client_assertion_type"];
        var formClientId = p["client_id"];

        var methods = (usedBasic ? 1 : 0) + (postSecret is not null ? 1 : 0) + (assertion is not null || assertionType is not null ? 1 : 0);
        if (methods > 1)
            return ClientAuthResult.Fail(OAuthErrors.InvalidRequest, "Only one client authentication method may be used.", usedBasic);

        if (usedBasic)
        {
            if (formClientId is not null && !string.Equals(formClientId, basicId, StringComparison.Ordinal))
                return ClientAuthResult.Fail(OAuthErrors.InvalidRequest, "client_id does not match the authenticated client.", basic: true);
            return await AuthenticateSecretAsync(basicId!, basicSecret!, ClientAuthMethods.SecretBasic, basic: true, ip, ct).ConfigureAwait(false);
        }

        if (postSecret is not null)
        {
            if (formClientId is null)
                return ClientAuthResult.Fail(OAuthErrors.InvalidClient, "client_id is required.");
            return await AuthenticateSecretAsync(formClientId, postSecret, ClientAuthMethods.SecretPost, basic: false, ip, ct).ConfigureAwait(false);
        }

        if (assertion is not null || assertionType is not null)
        {
            if (!string.Equals(assertionType, JwtBearerAssertionType, StringComparison.Ordinal) || assertion is null)
                return ClientAuthResult.Fail(OAuthErrors.InvalidClient, "Unsupported client assertion.");
            var result = await assertions.ValidateAsync(assertion, endpointUrl, ct).ConfigureAwait(false);
            if (result.Succeeded && formClientId is not null && !string.Equals(formClientId, result.Client!.ClientId, StringComparison.Ordinal))
                return ClientAuthResult.Fail(OAuthErrors.InvalidClient, "client_id does not match the client assertion.");
            if (!result.Succeeded) Log.ClientAuthFailed(logger, "private_key_jwt", result.Description ?? "", ip);
            return result;
        }

        // No credentials: only public clients (PKCE-protected) may identify themselves with client_id alone.
        if (formClientId is null)
            return ClientAuthResult.Fail(OAuthErrors.InvalidClient, "Client authentication is required.");
        var client = await clients.FindAsync(formClientId, ct).ConfigureAwait(false);
        if (client is null || !client.IsEnabled || client.IsConfidential || client.TokenEndpointAuthMethod != ClientAuthMethods.None)
        {
            Log.ClientAuthFailed(logger, "none", "unknown, disabled or confidential client", ip);
            return ClientAuthResult.Fail(OAuthErrors.InvalidClient, "Client authentication failed.");
        }
        return new ClientAuthResult(client, null, null, false, ClientAuthMethods.None);
    }

    private async Task<ClientAuthResult> AuthenticateSecretAsync(string clientId, string secret, string method, bool basic, string ip, CancellationToken ct)
    {
        var client = await clients.FindAsync(clientId, ct).ConfigureAwait(false);
        if (client is null || !client.IsEnabled || client.TokenEndpointAuthMethod != method || secret.Length > 256)
        {
            Log.ClientAuthFailed(logger, method, "unknown, disabled client or method not registered", ip);
            return ClientAuthResult.Fail(OAuthErrors.InvalidClient, "Client authentication failed.", basic);
        }

        var now = time.GetUtcNow();
        var hash = TokenHasher.Hash(secret);
        var ok = false;
        foreach (var s in client.Secrets)
        {
            // Evaluate every secret (no early exit) to keep timing independent of which secret matched.
            if ((s.ExpiresAt is null || s.ExpiresAt > now) && s.SecretHash.Length == 32
                && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(hash, s.SecretHash))
            {
                ok = true;
            }
        }

        if (!ok)
        {
            Log.ClientAuthFailed(logger, method, "invalid secret for " + client.ClientId, ip);
            return ClientAuthResult.Fail(OAuthErrors.InvalidClient, "Client authentication failed.", basic);
        }
        return new ClientAuthResult(client, null, null, basic, method);
    }

    /// <summary>RFC 6749 §2.3.1: id and secret are form-urlencoded before base64 encoding.</summary>
    internal static bool TryParseBasic(ReadOnlySpan<char> encoded, out string? clientId, out string? secret)
    {
        clientId = secret = null;
        if (encoded.Length is 0 or > 1024) return false;
        var buffer = new byte[encoded.Length];
        if (!Convert.TryFromBase64Chars(encoded, buffer, out var written)) return false;
        string decoded;
        try
        {
            decoded = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(buffer, 0, written);
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
        var colon = decoded.IndexOf(':', StringComparison.Ordinal);
        if (colon <= 0) return false;
        clientId = WebUtility.UrlDecode(decoded[..colon]);
        secret = WebUtility.UrlDecode(decoded[(colon + 1)..]);
        return clientId.Length > 0 && secret.Length > 0;
    }
}

/// <summary>RFC 7523 private_key_jwt client assertions with replay protection.</summary>
public sealed class ClientAssertionValidator(
    ClientCatalog clients,
    IGrantStore grants,
    IMemoryCache cache,
    IOptions<AuthServerOptions> options,
    TimeProvider time)
{
    public const int MaxAssertionLength = 8192;

    private static readonly string[] AllowedAlgorithms =
    [
        SecurityAlgorithms.RsaSha256, SecurityAlgorithms.RsaSha384, SecurityAlgorithms.RsaSha512,
        SecurityAlgorithms.RsaSsaPssSha256, SecurityAlgorithms.RsaSsaPssSha384, SecurityAlgorithms.RsaSsaPssSha512,
        SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.EcdsaSha384, SecurityAlgorithms.EcdsaSha512,
    ];

    private readonly JsonWebTokenHandler _handler = new();
    private readonly AuthServerOptions _options = options.Value;

    public async Task<ClientAuthResult> ValidateAsync(string assertion, string endpointUrl, CancellationToken ct)
    {
        static ClientAuthResult Fail(string why) => ClientAuthResult.Fail(OAuthErrors.InvalidClient, why);

        if (assertion.Length > MaxAssertionLength) return Fail("Client assertion too large.");

        JsonWebToken unverified;
        try
        {
            unverified = new JsonWebToken(assertion);
        }
        catch (ArgumentException)
        {
            return Fail("Malformed client assertion.");
        }

        var clientId = unverified.Issuer;
        if (string.IsNullOrEmpty(clientId) || !string.Equals(clientId, unverified.Subject, StringComparison.Ordinal))
            return Fail("Client assertion iss and sub must equal the client_id.");

        var client = await clients.FindAsync(clientId, ct).ConfigureAwait(false);
        if (client is null || !client.IsEnabled || client.TokenEndpointAuthMethod != ClientAuthMethods.PrivateKeyJwt || string.IsNullOrEmpty(client.Jwks))
            return Fail("Client authentication failed.");

        var keys = GetKeys(client);
        if (keys.Count == 0) return Fail("Client has no usable keys.");

        var issuer = _options.Issuer;
        var parameters = new TokenValidationParameters
        {
            ValidIssuer = client.ClientId,
            ValidAudiences = [endpointUrl, issuer + "/oauth2/token", issuer],
            IssuerSigningKeys = keys,
            ValidAlgorithms = AllowedAlgorithms,
            TryAllIssuerSigningKeys = true,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ValidateLifetime = false, // checked below against the injected clock with tighter bounds
            ValidateIssuerSigningKey = false,
        };

        var result = await _handler.ValidateTokenAsync(assertion, parameters).ConfigureAwait(false);
        if (!result.IsValid) return Fail("Client assertion validation failed.");

        var now = time.GetUtcNow();
        var skew = TimeSpan.FromSeconds(_options.Tokens.ClockSkewSeconds);
        var exp = new DateTimeOffset(unverified.ValidTo, TimeSpan.Zero);
        if (unverified.ValidTo == DateTime.MinValue || exp + skew < now) return Fail("Client assertion expired.");
        if (exp - now > TimeSpan.FromSeconds(_options.Tokens.ClientAssertionMaxLifetimeSeconds) + skew)
            return Fail("Client assertion lifetime too long.");
        if (unverified.ValidFrom != DateTime.MinValue && new DateTimeOffset(unverified.ValidFrom, TimeSpan.Zero) > now + skew)
            return Fail("Client assertion not yet valid.");
        if (unverified.IssuedAt != DateTime.MinValue && new DateTimeOffset(unverified.IssuedAt, TimeSpan.Zero) > now + skew)
            return Fail("Client assertion issued in the future.");

        var jti = unverified.Id;
        if (string.IsNullOrEmpty(jti) || jti.Length > 256) return Fail("Client assertion jti is required.");
        if (!await grants.TryRegisterClientAssertionAsync(client.ClientId, jti, exp + skew, ct).ConfigureAwait(false))
            return Fail("Client assertion replayed.");

        return new ClientAuthResult(client, null, null, false, ClientAuthMethods.PrivateKeyJwt);
    }

    private IList<SecurityKey> GetKeys(ClientApplication client)
    {
        var cacheKey = "jwks:" + client.ClientId;
        if (cache.TryGetValue(cacheKey, out (string Json, IList<SecurityKey> Keys) cached) && ReferenceEquals(cached.Json, client.Jwks))
            return cached.Keys;

        var keys = ClientJwks.TryParse(client.Jwks!, out var parsed, out _) ? parsed : [];
        using var entry = cache.CreateEntry(cacheKey);
        entry.Value = (client.Jwks!, keys);
        entry.Size = 1;
        entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10);
        return keys;
    }
}

public static class ClientJwks
{
    /// <summary>
    /// Accepts only public asymmetric signature keys: RSA >= 2048 bits or EC P-256/384/521.
    /// Symmetric ("oct") keys and any private key material are rejected.
    /// </summary>
    public static bool TryParse(string json, out IList<SecurityKey> keys, out string? error)
    {
        keys = [];
        error = null;
        JsonWebKeySet set;
        try
        {
            set = new JsonWebKeySet(json);
        }
        catch (Exception ex) when (ex is ArgumentException or System.Text.Json.JsonException or FormatException or InvalidOperationException)
        {
            error = "jwks is not a valid JSON Web Key Set.";
            return false;
        }

        var result = new List<SecurityKey>();
        foreach (var key in set.Keys)
        {
            if (!string.IsNullOrEmpty(key.D) || !string.IsNullOrEmpty(key.P) || !string.IsNullOrEmpty(key.Q) || !string.IsNullOrEmpty(key.K))
            {
                error = "jwks must not contain private or symmetric key material.";
                return false;
            }
            if (key.Use is not null && key.Use != "sig") continue;

            if (key.Kty == JsonWebAlgorithmsKeyTypes.RSA && !string.IsNullOrEmpty(key.N) && !string.IsNullOrEmpty(key.E))
            {
                if (Base64UrlEncoder.DecodeBytes(key.N).Length * 8 < 2048)
                {
                    error = "RSA keys must be at least 2048 bits.";
                    return false;
                }
                result.Add(key);
            }
            else if (key.Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve && key.Crv is "P-256" or "P-384" or "P-521"
                     && !string.IsNullOrEmpty(key.X) && !string.IsNullOrEmpty(key.Y))
            {
                result.Add(key);
            }
        }

        if (result.Count == 0)
        {
            error = "jwks contains no usable RSA/EC signature key.";
            return false;
        }
        keys = result;
        return true;
    }
}
