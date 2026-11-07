using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using AddAccion.Auth.Configuration;
using AddAccion.Auth.Crypto;
using AddAccion.Auth.Domain;
using AddAccion.Auth.Persistence;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AddAccion.Auth.Protocol;

public sealed record AccessTokenSpec
{
    public required string Subject { get; init; }
    public required string ClientId { get; init; }
    public required IReadOnlyList<string> Scopes { get; init; }
    public required IReadOnlyList<string> Audiences { get; init; }
    public required DateTimeOffset IssuedAt { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public required string Jti { get; init; }
    public DateTimeOffset? AuthTime { get; init; }
    public IReadOnlyList<string>? Roles { get; init; }
}

/// <summary>
/// Issues JWT access tokens following the RFC 9068 profile (typ "at+jwt") and OIDC ID tokens.
/// Claims are kept minimal: resource servers get identity + authorization data, not profile PII.
/// </summary>
public sealed class TokenService(SigningKeyStore keys, IOptions<AuthServerOptions> options)
{
    public const string AccessTokenType = "at+jwt";

    private readonly JsonWebTokenHandler _handler = new() { SetDefaultTimesOnTokenCreation = false };
    private readonly string _issuer = options.Value.Issuer;
    private readonly int _idTokenLifetime = options.Value.Tokens.IdTokenLifetimeSeconds;

    public static string NewJti() => RandomTokens.Create(16);

    public string CreateAccessToken(AccessTokenSpec spec)
    {
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [JwtRegisteredClaimNames.Sub] = spec.Subject,
            [JwtRegisteredClaimNames.Jti] = spec.Jti,
            ["client_id"] = spec.ClientId,
            ["scope"] = ScopeParser.Join(spec.Scopes),
        };
        if (spec.AuthTime is { } authTime) claims[JwtRegisteredClaimNames.AuthTime] = authTime.ToUnixTimeSeconds();
        if (spec.Roles is { Count: > 0 } roles) claims["roles"] = roles.ToArray();

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            IssuedAt = spec.IssuedAt.UtcDateTime,
            Expires = spec.ExpiresAt.UtcDateTime,
            TokenType = AccessTokenType,
            Claims = claims,
            SigningCredentials = keys.ActiveCredentials,
        };
        foreach (var aud in spec.Audiences.Count > 0 ? spec.Audiences : [_issuer]) descriptor.Audiences.Add(aud);
        return _handler.CreateToken(descriptor);
    }

    public string CreateIdToken(UserAccount user, string clientId, IReadOnlyList<string> scopes, string? nonce, DateTimeOffset authTime, DateTimeOffset now, string accessToken)
    {
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [JwtRegisteredClaimNames.Sub] = user.UserId,
            [JwtRegisteredClaimNames.AuthTime] = authTime.ToUnixTimeSeconds(),
            ["at_hash"] = AtHash(accessToken, keys.Active.Algorithm),
        };
        if (!string.IsNullOrEmpty(nonce)) claims[JwtRegisteredClaimNames.Nonce] = nonce;
        UserClaims.AddTo(claims, user, scopes);

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = clientId,
            IssuedAt = now.UtcDateTime,
            Expires = now.AddSeconds(_idTokenLifetime).UtcDateTime,
            TokenType = "JWT",
            Claims = claims,
            SigningCredentials = keys.ActiveCredentials,
        };
        return _handler.CreateToken(descriptor);
    }

    /// <summary>OIDC Core §3.1.3.6: base64url of the left-most half of the hash of the access token.</summary>
    internal static string AtHash(string accessToken, string algorithm)
    {
        var bytes = Encoding.ASCII.GetBytes(accessToken);
        byte[] hash = algorithm switch
        {
            SecurityAlgorithms.EcdsaSha384 or SecurityAlgorithms.RsaSha384 => SHA384.HashData(bytes),
            SecurityAlgorithms.EcdsaSha512 or SecurityAlgorithms.RsaSha512 => SHA512.HashData(bytes),
            _ => SHA256.HashData(bytes),
        };
        return Base64Url.EncodeToString(hash.AsSpan(0, hash.Length / 2));
    }
}

/// <summary>Scope-driven user claims shared by the ID token and the UserInfo endpoint.</summary>
public static class UserClaims
{
    public static void AddTo(IDictionary<string, object> claims, UserAccount user, IReadOnlyList<string> scopes)
    {
        if (ScopeParser.Contains(scopes, StandardScopes.Profile))
        {
            Add(claims, "name", user.DisplayName);
            Add(claims, "given_name", user.GivenName);
            Add(claims, "family_name", user.FamilyName);
            Add(claims, "preferred_username", user.LoginName);
        }
        if (ScopeParser.Contains(scopes, StandardScopes.Email) && !string.IsNullOrEmpty(user.Email))
        {
            claims["email"] = user.Email;
            claims["email_verified"] = user.EmailVerified;
        }
        if (ScopeParser.Contains(scopes, StandardScopes.Roles) && user.Roles.Count > 0)
        {
            claims["roles"] = user.Roles.ToArray();
        }
    }

    private static void Add(IDictionary<string, object> claims, string name, string? value)
    {
        if (!string.IsNullOrEmpty(value)) claims[name] = value;
    }
}

public sealed record ValidatedAccessToken(
    string Subject,
    string ClientId,
    IReadOnlyList<string> Scopes,
    IReadOnlyList<string> Audiences,
    string Jti,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    IReadOnlyList<string> Roles);

/// <summary>Validates access tokens issued by this server (introspection, userinfo, admin API, revocation).</summary>
public sealed class AccessTokenValidator
{
    public const int MaxTokenLength = 8192;

    private readonly JsonWebTokenHandler _handler = new();
    private readonly TokenValidationParameters _parameters;
    private readonly IGrantStore _grants;
    private readonly TimeProvider _time;
    private readonly TimeSpan _skew;

    public AccessTokenValidator(SigningKeyStore keys, IGrantStore grants, IOptions<AuthServerOptions> options, TimeProvider time)
    {
        _grants = grants;
        _time = time;
        _skew = TimeSpan.FromSeconds(options.Value.Tokens.ClockSkewSeconds);
        _parameters = new TokenValidationParameters
        {
            ValidIssuer = options.Value.Issuer,
            ValidateAudience = false, // each caller checks the audience it requires
            IssuerSigningKeys = keys.ValidationKeys,
            ValidAlgorithms = keys.Algorithms,
            ValidTypes = [TokenService.AccessTokenType],
            TryAllIssuerSigningKeys = false, // kid must match a published key
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ValidateLifetime = false, // checked against the injected clock
            ValidateIssuerSigningKey = false,
        };
    }

    public static bool LooksLikeJwt(string token) => token.Count(c => c == '.') == 2;

    public async Task<ValidatedAccessToken?> ValidateAsync(string token, bool checkRevocation, CancellationToken ct)
    {
        if (token.Length is 0 or > MaxTokenLength || !LooksLikeJwt(token)) return null;

        var result = await _handler.ValidateTokenAsync(token, _parameters).ConfigureAwait(false);
        if (!result.IsValid || result.SecurityToken is not JsonWebToken jwt) return null;

        var expires = new DateTimeOffset(jwt.ValidTo, TimeSpan.Zero);
        if (jwt.ValidTo == DateTime.MinValue || expires + _skew <= _time.GetUtcNow()) return null;

        var jti = jwt.Id;
        if (string.IsNullOrEmpty(jti)) return null;
        if (!jwt.TryGetPayloadValue<string>("client_id", out var clientId) || string.IsNullOrEmpty(clientId)) return null;
        jwt.TryGetPayloadValue<string>("scope", out var scope);
        _ = ScopeParser.TryParse(scope, out var scopes);

        var roles = new List<string>();
        if (jwt.TryGetPayloadValue<string[]>("roles", out var r) && r is not null) roles.AddRange(r);

        if (checkRevocation && await _grants.IsAccessTokenRevokedAsync(jti, ct).ConfigureAwait(false)) return null;

        return new ValidatedAccessToken(
            jwt.Subject,
            clientId,
            scopes,
            jwt.Audiences.ToArray(),
            jti,
            new DateTimeOffset(jwt.IssuedAt, TimeSpan.Zero),
            expires,
            roles);
    }
}
