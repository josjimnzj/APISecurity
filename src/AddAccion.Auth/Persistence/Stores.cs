using AddAccion.Auth.Domain;

namespace AddAccion.Auth.Persistence;

/// <summary>Registered OAuth clients.</summary>
public interface IClientStore
{
    Task<ClientApplication?> FindAsync(string clientId, CancellationToken ct);
    Task<bool> CreateAsync(ClientApplication client, CancellationToken ct);
    Task<int> AddSecretAsync(string clientId, byte[] secretHash, string? description, DateTimeOffset createdAt, DateTimeOffset? expiresAt, CancellationToken ct);
    Task<bool> DeleteSecretAsync(string clientId, int secretId, CancellationToken ct);
    Task<bool> SetEnabledAsync(string clientId, bool enabled, DateTimeOffset now, CancellationToken ct);
}

/// <summary>API scopes / resources (audiences).</summary>
public interface IScopeStore
{
    Task<IReadOnlyList<ScopeDefinition>> GetAllAsync(CancellationToken ct);
}

/// <summary>Read-only access to AddACCION users (through auth.vw_Users) plus brute-force state.</summary>
public interface IUserStore
{
    /// <summary>Lookup by login name. Includes lockout state; roles are not loaded.</summary>
    Task<UserAccount?> FindByLoginAsync(string loginName, CancellationToken ct);

    /// <summary>Lookup by stable id, including roles.</summary>
    Task<UserAccount?> FindByIdAsync(string userId, CancellationToken ct);

    /// <summary>Atomically registers a failed attempt. Returns the lockout end when the account becomes locked.</summary>
    Task<DateTimeOffset?> RecordFailedLoginAsync(string userId, DateTimeOffset now, int maxAttempts, TimeSpan lockout, CancellationToken ct);

    Task RecordSuccessfulLoginAsync(string userId, DateTimeOffset now, CancellationToken ct);
}

/// <summary>Short-lived grants: authorization codes, refresh tokens, revocations, assertion replay cache.</summary>
public interface IGrantStore
{
    Task CreateAuthorizationCodeAsync(AuthorizationCodeRecord code, CancellationToken ct);

    /// <summary>
    /// Atomically consumes a code if hash, client, redirect URI and PKCE challenge match and it is not expired.
    /// When the code was already consumed returns <see cref="CodeRedemptionStatus.Replayed"/> with the data
    /// recorded at first redemption so the caller can revoke it.
    /// </summary>
    Task<CodeRedemptionResult> RedeemAuthorizationCodeAsync(CodeRedemption redemption, CancellationToken ct);

    Task CreateRefreshTokenAsync(RefreshTokenRecord token, CancellationToken ct);
    Task<RefreshTokenRecord?> FindRefreshTokenAsync(byte[] tokenHash, CancellationToken ct);

    /// <summary>Marks <paramref name="currentId"/> consumed and inserts <paramref name="replacement"/> in one transaction. False if it was already consumed/revoked (race).</summary>
    Task<bool> RotateRefreshTokenAsync(long currentId, RefreshTokenRecord replacement, DateTimeOffset now, CancellationToken ct);

    Task<int> RevokeRefreshTokenFamilyAsync(Guid familyId, DateTimeOffset now, CancellationToken ct);

    Task RevokeAccessTokenAsync(string jti, DateTimeOffset expiresAt, CancellationToken ct);
    Task<bool> IsAccessTokenRevokedAsync(string jti, CancellationToken ct);

    /// <summary>Registers a client assertion jti. False when it was already used (replay).</summary>
    Task<bool> TryRegisterClientAssertionAsync(string clientId, string jti, DateTimeOffset expiresAt, CancellationToken ct);

    /// <summary>Deletes expired rows. Returns the number of rows removed.</summary>
    Task<int> CleanupAsync(DateTimeOffset now, int batchSize, CancellationToken ct);
}

public interface IDatabaseHealth
{
    Task<bool> PingAsync(CancellationToken ct);
}
