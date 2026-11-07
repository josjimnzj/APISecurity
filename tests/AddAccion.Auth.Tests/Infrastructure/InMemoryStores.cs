using System.Collections.Concurrent;
using AddAccion.Auth.Domain;
using AddAccion.Auth.Persistence;

namespace AddAccion.Auth.Tests.Infrastructure;

/// <summary>In-memory stores with the same atomicity guarantees as the SQL Server implementation.</summary>
public sealed class InMemoryDatabase : IClientStore, IScopeStore, IUserStore, IGrantStore, IDatabaseHealth
{
    private readonly object _gate = new();
    private readonly Dictionary<string, ClientApplication> _clients = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ScopeDefinition> _scopes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, UserAccount> _users = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (int Failed, DateTimeOffset? LockoutEnd)> _loginState = new(StringComparer.Ordinal);
    private readonly List<AuthorizationCodeRecord> _codes = [];
    private readonly List<RefreshTokenRecord> _refresh = [];
    private readonly ConcurrentDictionary<string, DateTimeOffset> _revoked = new(StringComparer.Ordinal);
    private readonly Dictionary<(string, string), DateTimeOffset> _assertions = [];
    private int _secretId;
    private long _rowId;

    // ---- seeding helpers -------------------------------------------------
    public void AddScope(ScopeDefinition scope)
    {
        lock (_gate) _scopes[scope.Name] = scope;
    }

    public void AddUser(UserAccount user)
    {
        lock (_gate) _users[user.UserId] = user;
    }

    public void SetUserActive(string userId, bool active)
    {
        lock (_gate) _users[userId] = _users[userId] with { IsActive = active };
    }

    // ---- IClientStore ----------------------------------------------------
    public Task<ClientApplication?> FindAsync(string clientId, CancellationToken ct)
    {
        lock (_gate) return Task.FromResult(_clients.GetValueOrDefault(clientId));
    }

    public Task<bool> CreateAsync(ClientApplication client, CancellationToken ct)
    {
        lock (_gate)
        {
            if (_clients.ContainsKey(client.ClientId)) return Task.FromResult(false);
            var secrets = client.Secrets.Select(s => s with { Id = ++_secretId }).ToArray();
            _clients[client.ClientId] = client with { Secrets = secrets };
            return Task.FromResult(true);
        }
    }

    public Task<int> AddSecretAsync(string clientId, byte[] secretHash, string? description, DateTimeOffset createdAt, DateTimeOffset? expiresAt, CancellationToken ct)
    {
        lock (_gate)
        {
            if (!_clients.TryGetValue(clientId, out var c)) return Task.FromResult(0);
            var id = ++_secretId;
            _clients[clientId] = c with { Secrets = [.. c.Secrets, new ClientSecretInfo(id, secretHash, description, createdAt, expiresAt)] };
            return Task.FromResult(id);
        }
    }

    public Task<bool> DeleteSecretAsync(string clientId, int secretId, CancellationToken ct)
    {
        lock (_gate)
        {
            if (!_clients.TryGetValue(clientId, out var c) || c.Secrets.All(s => s.Id != secretId)) return Task.FromResult(false);
            _clients[clientId] = c with { Secrets = c.Secrets.Where(s => s.Id != secretId).ToArray() };
            return Task.FromResult(true);
        }
    }

    public Task<bool> SetEnabledAsync(string clientId, bool enabled, DateTimeOffset now, CancellationToken ct)
    {
        lock (_gate)
        {
            if (!_clients.TryGetValue(clientId, out var c)) return Task.FromResult(false);
            _clients[clientId] = c with { IsEnabled = enabled };
            return Task.FromResult(true);
        }
    }

    // ---- IScopeStore -----------------------------------------------------
    public Task<IReadOnlyList<ScopeDefinition>> GetAllAsync(CancellationToken ct)
    {
        lock (_gate) return Task.FromResult<IReadOnlyList<ScopeDefinition>>(_scopes.Values.ToArray());
    }

    // ---- IUserStore ------------------------------------------------------
    public Task<UserAccount?> FindByLoginAsync(string loginName, CancellationToken ct)
    {
        lock (_gate)
        {
            // SQL Server default collations are case-insensitive: mirror that.
            var matches = _users.Values.Where(u => string.Equals(u.LoginName, loginName, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (matches.Length != 1) return Task.FromResult<UserAccount?>(null);
            return Task.FromResult<UserAccount?>(WithLockout(matches[0]) with { Roles = [] });
        }
    }

    public Task<UserAccount?> FindByIdAsync(string userId, CancellationToken ct)
    {
        lock (_gate) return Task.FromResult(_users.TryGetValue(userId, out var u) ? WithLockout(u) : null);
    }

    private UserAccount WithLockout(UserAccount u) =>
        u with { LockoutEnd = _loginState.TryGetValue(u.UserId, out var s) ? s.LockoutEnd : null };

    public Task<DateTimeOffset?> RecordFailedLoginAsync(string userId, DateTimeOffset now, int maxAttempts, TimeSpan lockout, CancellationToken ct)
    {
        lock (_gate)
        {
            _loginState.TryGetValue(userId, out var s);
            var count = s.LockoutEnd is { } end && end <= now ? 1 : s.Failed + 1;
            DateTimeOffset? lockEnd = count >= maxAttempts ? now + lockout : null;
            _loginState[userId] = (count, lockEnd);
            return Task.FromResult(lockEnd);
        }
    }

    public Task RecordSuccessfulLoginAsync(string userId, DateTimeOffset now, CancellationToken ct)
    {
        lock (_gate) _loginState.Remove(userId);
        return Task.CompletedTask;
    }

    // ---- IGrantStore -----------------------------------------------------
    public Task CreateAuthorizationCodeAsync(AuthorizationCodeRecord code, CancellationToken ct)
    {
        lock (_gate) _codes.Add(code with { Id = ++_rowId });
        return Task.CompletedTask;
    }

    public Task<CodeRedemptionResult> RedeemAuthorizationCodeAsync(CodeRedemption x, CancellationToken ct)
    {
        lock (_gate)
        {
            var i = _codes.FindIndex(c => c.CodeHash.AsSpan().SequenceEqual(x.CodeHash));
            if (i < 0) return Task.FromResult(new CodeRedemptionResult(CodeRedemptionStatus.Invalid, null));
            var c = _codes[i];
            if (c.ConsumedAt is not null) return Task.FromResult(new CodeRedemptionResult(CodeRedemptionStatus.Replayed, c));
            if (c.ExpiresAt <= x.Now || c.ClientId != x.ClientId || c.RedirectUri != x.RedirectUri || c.CodeChallenge != x.CodeChallenge)
                return Task.FromResult(new CodeRedemptionResult(CodeRedemptionStatus.Invalid, null));
            var consumed = c with { ConsumedAt = x.Now, RefreshFamilyId = x.RefreshFamilyId, AccessTokenJti = x.AccessTokenJti, AccessTokenExpiresAt = x.AccessTokenExpiresAt };
            _codes[i] = consumed;
            return Task.FromResult(new CodeRedemptionResult(CodeRedemptionStatus.Redeemed, consumed));
        }
    }

    public Task CreateRefreshTokenAsync(RefreshTokenRecord token, CancellationToken ct)
    {
        lock (_gate) _refresh.Add(token with { Id = ++_rowId });
        return Task.CompletedTask;
    }

    public Task<RefreshTokenRecord?> FindRefreshTokenAsync(byte[] tokenHash, CancellationToken ct)
    {
        lock (_gate) return Task.FromResult(_refresh.FirstOrDefault(t => t.TokenHash.AsSpan().SequenceEqual(tokenHash)));
    }

    public Task<bool> RotateRefreshTokenAsync(long currentId, RefreshTokenRecord replacement, DateTimeOffset now, CancellationToken ct)
    {
        lock (_gate)
        {
            var i = _refresh.FindIndex(t => t.Id == currentId);
            if (i < 0 || _refresh[i].ConsumedAt is not null || _refresh[i].RevokedAt is not null) return Task.FromResult(false);
            _refresh[i] = _refresh[i] with { ConsumedAt = now };
            _refresh.Add(replacement with { Id = ++_rowId });
            return Task.FromResult(true);
        }
    }

    public Task<int> RevokeRefreshTokenFamilyAsync(Guid familyId, DateTimeOffset now, CancellationToken ct)
    {
        lock (_gate)
        {
            var n = 0;
            for (var i = 0; i < _refresh.Count; i++)
            {
                if (_refresh[i].FamilyId == familyId && _refresh[i].RevokedAt is null)
                {
                    _refresh[i] = _refresh[i] with { RevokedAt = now };
                    n++;
                }
            }
            return Task.FromResult(n);
        }
    }

    public Task RevokeAccessTokenAsync(string jti, DateTimeOffset expiresAt, CancellationToken ct)
    {
        _revoked.TryAdd(jti, expiresAt);
        return Task.CompletedTask;
    }

    public Task<bool> IsAccessTokenRevokedAsync(string jti, CancellationToken ct) => Task.FromResult(_revoked.ContainsKey(jti));

    public Task<bool> TryRegisterClientAssertionAsync(string clientId, string jti, DateTimeOffset expiresAt, CancellationToken ct)
    {
        lock (_gate) return Task.FromResult(_assertions.TryAdd((clientId, jti), expiresAt));
    }

    public Task<int> CleanupAsync(DateTimeOffset now, int batchSize, CancellationToken ct) => Task.FromResult(0);

    public Task<bool> PingAsync(CancellationToken ct) => Task.FromResult(true);
}
