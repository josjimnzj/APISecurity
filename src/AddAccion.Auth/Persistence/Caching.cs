using AddAccion.Auth.Configuration;
using AddAccion.Auth.Domain;
using AddAccion.Auth.Protocol;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace AddAccion.Auth.Persistence;

/// <summary>
/// Read-through cache for clients: the client_credentials hot path needs no database round trip.
/// Changes made through the admin API evict the local entry; other replicas converge within ClientCacheSeconds.
/// Unknown client ids are negatively cached for a short time to absorb random-id floods.
/// </summary>
public sealed class ClientCatalog(IClientStore store, IMemoryCache cache, IOptions<AuthServerOptions> options)
{
    private static readonly object Missing = new();
    private readonly TimeSpan _ttl = TimeSpan.FromSeconds(options.Value.Caching.ClientCacheSeconds);
    private readonly TimeSpan _negativeTtl = TimeSpan.FromSeconds(Math.Min(10, options.Value.Caching.ClientCacheSeconds));

    public async ValueTask<ClientApplication?> FindAsync(string clientId, CancellationToken ct)
    {
        if (clientId.Length is 0 or > 100) return null;
        var key = CacheKey(clientId);
        if (_ttl > TimeSpan.Zero && cache.TryGetValue(key, out var cached))
            return cached as ClientApplication;

        var client = await store.FindAsync(clientId, ct).ConfigureAwait(false);
        if (_ttl > TimeSpan.Zero)
        {
            using var entry = cache.CreateEntry(key);
            entry.Value = client ?? Missing;
            entry.Size = 1;
            entry.AbsoluteExpirationRelativeToNow = client is null ? _negativeTtl : _ttl;
        }
        return client;
    }

    public void Evict(string clientId) => cache.Remove(CacheKey(clientId));

    private static string CacheKey(string clientId) => "client:" + clientId;
}

/// <summary>Snapshot of API scopes (name -> audience), refreshed in the background of requests.</summary>
public sealed class ScopeCatalog(IScopeStore store, IOptions<AuthServerOptions> options, TimeProvider time) : IDisposable
{
    private readonly TimeSpan _ttl = TimeSpan.FromSeconds(Math.Max(1, options.Value.Caching.ScopeCacheSeconds));
    private readonly SemaphoreSlim _refresh = new(1, 1);
    private volatile ScopeSnapshot? _snapshot;

    public async ValueTask<ScopeSnapshot> GetAsync(CancellationToken ct)
    {
        var current = _snapshot;
        if (current is not null && current.ExpiresAt > time.GetUtcNow()) return current;

        if (current is not null)
        {
            // Stale: one caller refreshes, the rest keep using the stale snapshot.
            if (!await _refresh.WaitAsync(0, ct).ConfigureAwait(false)) return current;
        }
        else
        {
            await _refresh.WaitAsync(ct).ConfigureAwait(false);
        }

        try
        {
            current = _snapshot;
            if (current is not null && current.ExpiresAt > time.GetUtcNow()) return current;
            var scopes = await store.GetAllAsync(ct).ConfigureAwait(false);
            var snapshot = new ScopeSnapshot(scopes, time.GetUtcNow() + _ttl);
            _snapshot = snapshot;
            return snapshot;
        }
        finally
        {
            _refresh.Release();
        }
    }

    public void Invalidate() => _snapshot = null;

    public void Dispose() => _refresh.Dispose();
}

public sealed class ScopeSnapshot
{
    private readonly Dictionary<string, ScopeDefinition> _api;

    public DateTimeOffset ExpiresAt { get; }

    public ScopeSnapshot(IEnumerable<ScopeDefinition> scopes, DateTimeOffset expiresAt)
    {
        _api = scopes.Where(s => s.IsEnabled).ToDictionary(s => s.Name, StringComparer.Ordinal);
        ExpiresAt = expiresAt;
    }

    public IEnumerable<string> ApiScopeNames => _api.Keys;

    public bool IsApiScope(string scope) => _api.ContainsKey(scope);

    public bool IsKnown(string scope) => StandardScopes.IsIdentityScope(scope) || _api.ContainsKey(scope);

    /// <summary>Distinct audiences of the API scopes in <paramref name="scopes"/>, in request order.</summary>
    public List<string> AudiencesFor(IEnumerable<string> scopes)
    {
        var audiences = new List<string>();
        foreach (var s in scopes)
        {
            if (_api.TryGetValue(s, out var def) && !audiences.Contains(def.Audience, StringComparer.Ordinal))
                audiences.Add(def.Audience);
        }
        return audiences;
    }
}
