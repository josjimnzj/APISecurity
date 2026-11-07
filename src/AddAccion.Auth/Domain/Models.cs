namespace AddAccion.Auth.Domain;

public enum ClientType : byte
{
    Confidential = 1,
    Public = 2,
}

public static class GrantTypes
{
    public const string AuthorizationCode = "authorization_code";
    public const string RefreshToken = "refresh_token";
    public const string ClientCredentials = "client_credentials";

    public static readonly string[] All = [AuthorizationCode, RefreshToken, ClientCredentials];
}

public static class ClientAuthMethods
{
    public const string SecretBasic = "client_secret_basic";
    public const string SecretPost = "client_secret_post";
    public const string PrivateKeyJwt = "private_key_jwt";
    public const string None = "none";

    public static readonly string[] All = [SecretBasic, SecretPost, PrivateKeyJwt, None];
}

public sealed record ClientSecretInfo(int Id, byte[] SecretHash, string? Description, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt);

public sealed record ClientApplication
{
    public required string ClientId { get; init; }
    public required string ClientName { get; init; }
    public required ClientType ClientType { get; init; }
    public required string TokenEndpointAuthMethod { get; init; }
    public required IReadOnlyList<string> AllowedGrantTypes { get; init; }
    public required IReadOnlyList<string> RedirectUris { get; init; }
    public required IReadOnlyList<string> AllowedScopes { get; init; }
    public IReadOnlyList<ClientSecretInfo> Secrets { get; init; } = [];
    public string? Jwks { get; init; }
    public int AccessTokenLifetimeSeconds { get; init; } = 600;
    public int RefreshTokenLifetimeSeconds { get; init; } = 2_592_000;
    public bool CanIntrospect { get; init; }
    public bool IsEnabled { get; init; } = true;

    public bool IsConfidential => ClientType == ClientType.Confidential;

    public bool AllowsGrant(string grantType)
    {
        foreach (var g in AllowedGrantTypes)
        {
            if (string.Equals(g, grantType, StringComparison.Ordinal)) return true;
        }
        return false;
    }

    public bool AllowsScope(string scope)
    {
        foreach (var s in AllowedScopes)
        {
            if (string.Equals(s, scope, StringComparison.Ordinal)) return true;
        }
        return false;
    }
}

public sealed record ScopeDefinition(string Name, string Audience, string? Description, bool IsEnabled);

public sealed record UserAccount
{
    public required string UserId { get; init; }
    public required string LoginName { get; init; }
    public string? Email { get; init; }
    public bool EmailVerified { get; init; }
    public string? DisplayName { get; init; }
    public string? GivenName { get; init; }
    public string? FamilyName { get; init; }
    public string? PasswordHash { get; init; }
    public bool IsActive { get; init; }
    public DateTimeOffset? LockoutEnd { get; init; }
    public IReadOnlyList<string> Roles { get; init; } = [];
}

public sealed record AuthorizationCodeRecord
{
    public long Id { get; init; }
    public required byte[] CodeHash { get; init; }
    public required string ClientId { get; init; }
    public required string UserId { get; init; }
    public required string RedirectUri { get; init; }
    public required string Scopes { get; init; }
    public required string CodeChallenge { get; init; }
    public string? Nonce { get; init; }
    public required DateTimeOffset AuthTime { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public DateTimeOffset? ConsumedAt { get; init; }
    public Guid? RefreshFamilyId { get; init; }
    public string? AccessTokenJti { get; init; }
    public DateTimeOffset? AccessTokenExpiresAt { get; init; }
}

/// <summary>Values written atomically when a code is redeemed, so a later replay can revoke what was issued.</summary>
public sealed record CodeRedemption(
    byte[] CodeHash,
    string ClientId,
    string RedirectUri,
    string CodeChallenge,
    DateTimeOffset Now,
    Guid RefreshFamilyId,
    string AccessTokenJti,
    DateTimeOffset AccessTokenExpiresAt);

public enum CodeRedemptionStatus
{
    Redeemed,
    Invalid,
    Replayed,
}

public sealed record CodeRedemptionResult(CodeRedemptionStatus Status, AuthorizationCodeRecord? Code);

public sealed record RefreshTokenRecord
{
    public long Id { get; init; }
    public required byte[] TokenHash { get; init; }
    public required Guid FamilyId { get; init; }
    public required string ClientId { get; init; }
    public required string UserId { get; init; }
    public required string Scopes { get; init; }
    public required DateTimeOffset AuthTime { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public DateTimeOffset? ConsumedAt { get; init; }
    public DateTimeOffset? RevokedAt { get; init; }
}
