using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using AddAccion.Auth.Crypto;
using AddAccion.Auth.Domain;
using AddAccion.Auth.Hosting;
using AddAccion.Auth.Persistence;
using AddAccion.Auth.Protocol;
using AddAccion.Auth.Security;

namespace AddAccion.Auth.Endpoints;

public sealed record CreateClientRequest
{
    [JsonPropertyName("client_id")] public string? ClientId { get; init; }
    [JsonPropertyName("client_name")] public string? ClientName { get; init; }
    [JsonPropertyName("client_type")] public string? ClientType { get; init; }
    [JsonPropertyName("token_endpoint_auth_method")] public string? TokenEndpointAuthMethod { get; init; }
    [JsonPropertyName("grant_types")] public string[]? GrantTypes { get; init; }
    [JsonPropertyName("redirect_uris")] public string[]? RedirectUris { get; init; }
    [JsonPropertyName("scopes")] public string[]? Scopes { get; init; }
    [JsonPropertyName("jwks")] public JsonElement? Jwks { get; init; }
    [JsonPropertyName("access_token_lifetime")] public int? AccessTokenLifetime { get; init; }
    [JsonPropertyName("refresh_token_lifetime")] public int? RefreshTokenLifetime { get; init; }
    [JsonPropertyName("can_introspect")] public bool? CanIntrospect { get; init; }
    [JsonPropertyName("secret_lifetime_days")] public int? SecretLifetimeDays { get; init; }
}

public sealed record CreateSecretRequest
{
    [JsonPropertyName("description")] public string? Description { get; init; }
    [JsonPropertyName("lifetime_days")] public int? LifetimeDays { get; init; }
}

public sealed record SecretView(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("description")] string? Description,
    [property: JsonPropertyName("created_at")] DateTimeOffset CreatedAt,
    [property: JsonPropertyName("expires_at")] DateTimeOffset? ExpiresAt);

public sealed record ClientView
{
    [JsonPropertyName("client_id")] public required string ClientId { get; init; }
    [JsonPropertyName("client_name")] public required string ClientName { get; init; }
    [JsonPropertyName("client_type")] public required string ClientType { get; init; }
    [JsonPropertyName("token_endpoint_auth_method")] public required string TokenEndpointAuthMethod { get; init; }
    [JsonPropertyName("grant_types")] public required IReadOnlyList<string> GrantTypes { get; init; }
    [JsonPropertyName("redirect_uris")] public required IReadOnlyList<string> RedirectUris { get; init; }
    [JsonPropertyName("scopes")] public required IReadOnlyList<string> Scopes { get; init; }
    [JsonPropertyName("access_token_lifetime")] public int AccessTokenLifetime { get; init; }
    [JsonPropertyName("refresh_token_lifetime")] public int RefreshTokenLifetime { get; init; }
    [JsonPropertyName("can_introspect")] public bool CanIntrospect { get; init; }
    [JsonPropertyName("enabled")] public bool Enabled { get; init; }
    [JsonPropertyName("has_jwks")] public bool HasJwks { get; init; }
    [JsonPropertyName("secrets")] public IReadOnlyList<SecretView> Secrets { get; init; } = [];

    /// <summary>Only present in the creation response. Shown once, never stored in clear.</summary>
    [JsonPropertyName("client_secret")] public string? ClientSecret { get; init; }

    public static ClientView From(ClientApplication c, string? secret = null) => new()
    {
        ClientId = c.ClientId,
        ClientName = c.ClientName,
        ClientType = c.IsConfidential ? "confidential" : "public",
        TokenEndpointAuthMethod = c.TokenEndpointAuthMethod,
        GrantTypes = c.AllowedGrantTypes,
        RedirectUris = c.RedirectUris,
        Scopes = c.AllowedScopes,
        AccessTokenLifetime = c.AccessTokenLifetimeSeconds,
        RefreshTokenLifetime = c.RefreshTokenLifetimeSeconds,
        CanIntrospect = c.CanIntrospect,
        Enabled = c.IsEnabled,
        HasJwks = !string.IsNullOrEmpty(c.Jwks),
        Secrets = c.Secrets.Select(s => new SecretView(s.Id, s.Description, s.CreatedAt, s.ExpiresAt)).ToArray(),
        ClientSecret = secret,
    };
}

public sealed record CreatedSecretView(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("client_secret")] string ClientSecret,
    [property: JsonPropertyName("expires_at")] DateTimeOffset? ExpiresAt);

/// <summary>Validation rules for registering clients (admin API and CLI share them).</summary>
public static partial class ClientRegistration
{
    public const string AdminScope = "auth.admin";
    public const string AdminAudience = "urn:addaccion:auth:admin";
    public const int DefaultSecretLifetimeDays = 365;

    [GeneratedRegex("^[A-Za-z0-9._-]{3,100}$", RegexOptions.CultureInvariant)]
    private static partial Regex ClientIdPattern();

    public static (ClientApplication? Client, string? Secret, string? Error) Build(CreateClientRequest r, ScopeSnapshot scopes, DateTimeOffset now)
    {
        if (r.ClientId is null || !ClientIdPattern().IsMatch(r.ClientId))
            return Err("client_id must match ^[A-Za-z0-9._-]{3,100}$.");
        if (string.IsNullOrWhiteSpace(r.ClientName) || r.ClientName.Length > 200)
            return Err("client_name is required (max 200 chars).");

        var type = r.ClientType switch
        {
            "confidential" => ClientType.Confidential,
            "public" => ClientType.Public,
            _ => (ClientType)0,
        };
        if (type == 0) return Err("client_type must be 'confidential' or 'public'.");

        var method = r.TokenEndpointAuthMethod ?? (type == ClientType.Public ? ClientAuthMethods.None : ClientAuthMethods.SecretBasic);
        if (!ClientAuthMethods.All.Contains(method)) return Err("Unsupported token_endpoint_auth_method.");
        if (type == ClientType.Public && method != ClientAuthMethods.None) return Err("Public clients must use token_endpoint_auth_method 'none'.");
        if (type == ClientType.Confidential && method == ClientAuthMethods.None) return Err("Confidential clients must authenticate.");

        var grants = (r.GrantTypes ?? []).Distinct(StringComparer.Ordinal).ToArray();
        if (grants.Length == 0 || grants.Any(g => !GrantTypes.All.Contains(g))) return Err("grant_types must be a non-empty subset of " + string.Join(", ", GrantTypes.All) + ".");
        if (type == ClientType.Public && grants.Contains(GrantTypes.ClientCredentials)) return Err("Public clients cannot use client_credentials.");
        if (grants.Contains(GrantTypes.RefreshToken) && !grants.Contains(GrantTypes.AuthorizationCode))
            return Err("refresh_token requires authorization_code.");

        var redirects = (r.RedirectUris ?? []).Distinct(StringComparer.Ordinal).ToArray();
        if (grants.Contains(GrantTypes.AuthorizationCode) && redirects.Length == 0) return Err("authorization_code requires at least one redirect_uri.");
        if (!grants.Contains(GrantTypes.AuthorizationCode) && redirects.Length > 0) return Err("redirect_uris are only valid with authorization_code.");
        foreach (var uri in redirects)
        {
            if (!RedirectUris.IsValidForRegistration(uri, out var reason)) return Err($"Invalid redirect_uri '{uri}': {reason}.");
        }

        var scopeList = (r.Scopes ?? []).Distinct(StringComparer.Ordinal).ToArray();
        if (scopeList.Length == 0) return Err("scopes must not be empty.");
        foreach (var s in scopeList)
        {
            if (!scopes.IsKnown(s)) return Err($"Unknown scope '{s}'.");
            if (StandardScopes.IsIdentityScope(s) && !grants.Contains(GrantTypes.AuthorizationCode))
                return Err($"Identity scope '{s}' requires authorization_code.");
        }

        string? jwks = null;
        if (r.Jwks is { ValueKind: JsonValueKind.Object } j)
        {
            jwks = j.GetRawText();
            if (jwks.Length > 32_768) return Err("jwks is too large.");
            if (!ClientJwks.TryParse(jwks, out _, out var jwksError)) return Err(jwksError!);
        }
        if (method == ClientAuthMethods.PrivateKeyJwt && jwks is null) return Err("private_key_jwt requires jwks.");
        if (method != ClientAuthMethods.PrivateKeyJwt && jwks is not null) return Err("jwks is only valid with private_key_jwt.");

        var at = r.AccessTokenLifetime ?? 600;
        var rt = r.RefreshTokenLifetime ?? 2_592_000;
        if (at is < 60 or > 86_400) return Err("access_token_lifetime must be 60..86400 seconds.");
        if (rt is < 300 or > 31_536_000) return Err("refresh_token_lifetime must be 300..31536000 seconds.");

        string? secret = null;
        var secrets = new List<ClientSecretInfo>();
        if (method is ClientAuthMethods.SecretBasic or ClientAuthMethods.SecretPost)
        {
            var days = r.SecretLifetimeDays ?? DefaultSecretLifetimeDays;
            if (days is < 1 or > 3650) return Err("secret_lifetime_days must be 1..3650.");
            secret = RandomTokens.CreateClientSecret();
            secrets.Add(new ClientSecretInfo(0, TokenHasher.Hash(secret), "initial", now, now.AddDays(days)));
        }

        var client = new ClientApplication
        {
            ClientId = r.ClientId,
            ClientName = r.ClientName.Trim(),
            ClientType = type,
            TokenEndpointAuthMethod = method,
            AllowedGrantTypes = grants,
            RedirectUris = redirects,
            AllowedScopes = scopeList,
            Secrets = secrets,
            Jwks = jwks,
            AccessTokenLifetimeSeconds = at,
            RefreshTokenLifetimeSeconds = rt,
            CanIntrospect = r.CanIntrospect ?? false,
            IsEnabled = true,
        };
        return (client, secret, null);

        static (ClientApplication?, string?, string?) Err(string e) => (null, null, e);
    }
}

/// <summary>Client administration API. Requires an access token with aud=urn:addaccion:auth:admin and scope auth.admin.</summary>
public static class AdminEndpoints
{
    public static void Map(IEndpointRouteBuilder app)
    {
        var group = app.MapGroup(Routes.Admin + "/clients").AddEndpointFilter(RequireAdminAsync).RequireRateLimiting("token");

        group.MapPost("", async (CreateClientRequest body, HttpContext ctx, IClientStore store, ClientCatalog catalog, ScopeCatalog scopes,
            TimeProvider time, ILogger<ClientView> logger) =>
        {
            var snapshot = await scopes.GetAsync(ctx.RequestAborted).ConfigureAwait(false);
            var (client, secret, error) = ClientRegistration.Build(body, snapshot, time.GetUtcNow());
            if (client is null) return OAuthResults.Error(ctx, "invalid_client_metadata", error);
            if (!await store.CreateAsync(client, ctx.RequestAborted).ConfigureAwait(false))
                return OAuthResults.Error(ctx, "invalid_client_metadata", "client_id already exists.", StatusCodes.Status409Conflict);
            catalog.Evict(client.ClientId);
            Log.AdminAction(logger, Actor(ctx), "client_created", client.ClientId);
            var created = await store.FindAsync(client.ClientId, ctx.RequestAborted).ConfigureAwait(false) ?? client;
            OAuthResults.NoStore(ctx);
            return TypedResults.Json(ClientView.From(created, secret), AuthJsonContext.Default.ClientView, statusCode: StatusCodes.Status201Created);
        });

        group.MapGet("/{clientId}", async (string clientId, HttpContext ctx, IClientStore store) =>
        {
            var client = await store.FindAsync(clientId, ctx.RequestAborted).ConfigureAwait(false);
            return client is null
                ? OAuthResults.Error(ctx, "not_found", "Client not found.", StatusCodes.Status404NotFound)
                : OAuthResults.Json(ctx, ClientView.From(client), AuthJsonContext.Default.ClientView);
        });

        group.MapPost("/{clientId}/secrets", async (string clientId, HttpContext ctx, IClientStore store, ClientCatalog catalog,
            TimeProvider time, ILogger<ClientView> logger) =>
        {
            CreateSecretRequest body = new();
            if (ctx.Request.ContentLength > 0)
            {
                body = await ctx.Request.ReadFromJsonAsync(AuthJsonContext.Default.CreateSecretRequest, ctx.RequestAborted).ConfigureAwait(false) ?? new();
            }
            var days = body.LifetimeDays ?? ClientRegistration.DefaultSecretLifetimeDays;
            if (days is < 1 or > 3650 || body.Description is { Length: > 200 })
                return OAuthResults.Error(ctx, "invalid_request", "lifetime_days must be 1..3650 and description max 200 chars.");

            var client = await store.FindAsync(clientId, ctx.RequestAborted).ConfigureAwait(false);
            if (client is null) return OAuthResults.Error(ctx, "not_found", "Client not found.", StatusCodes.Status404NotFound);
            if (client.TokenEndpointAuthMethod is not (ClientAuthMethods.SecretBasic or ClientAuthMethods.SecretPost))
                return OAuthResults.Error(ctx, "invalid_request", "Client does not authenticate with a secret.");

            var now = time.GetUtcNow();
            var secret = RandomTokens.CreateClientSecret();
            var expires = now.AddDays(days);
            var id = await store.AddSecretAsync(clientId, TokenHasher.Hash(secret), body.Description, now, expires, ctx.RequestAborted).ConfigureAwait(false);
            catalog.Evict(clientId);
            Log.AdminAction(logger, Actor(ctx), "secret_created", clientId);
            OAuthResults.NoStore(ctx);
            return TypedResults.Json(new CreatedSecretView(id, secret, expires), AuthJsonContext.Default.CreatedSecretView, statusCode: StatusCodes.Status201Created);
        });

        group.MapDelete("/{clientId}/secrets/{secretId:int}", async (string clientId, int secretId, HttpContext ctx, IClientStore store,
            ClientCatalog catalog, ILogger<ClientView> logger) =>
        {
            if (!await store.DeleteSecretAsync(clientId, secretId, ctx.RequestAborted).ConfigureAwait(false))
                return OAuthResults.Error(ctx, "not_found", "Secret not found.", StatusCodes.Status404NotFound);
            catalog.Evict(clientId);
            Log.AdminAction(logger, Actor(ctx), "secret_deleted", clientId);
            return TypedResults.NoContent();
        });

        group.MapPost("/{clientId}/disable", (string clientId, HttpContext ctx, IClientStore store, ClientCatalog catalog, TimeProvider time, ILogger<ClientView> logger) =>
            SetEnabledAsync(clientId, false, ctx, store, catalog, time, logger));
        group.MapPost("/{clientId}/enable", (string clientId, HttpContext ctx, IClientStore store, ClientCatalog catalog, TimeProvider time, ILogger<ClientView> logger) =>
            SetEnabledAsync(clientId, true, ctx, store, catalog, time, logger));
    }

    private static async Task<IResult> SetEnabledAsync(string clientId, bool enabled, HttpContext ctx, IClientStore store, ClientCatalog catalog,
        TimeProvider time, ILogger logger)
    {
        if (!await store.SetEnabledAsync(clientId, enabled, time.GetUtcNow(), ctx.RequestAborted).ConfigureAwait(false))
            return OAuthResults.Error(ctx, "not_found", "Client not found.", StatusCodes.Status404NotFound);
        catalog.Evict(clientId);
        Log.AdminAction(logger, Actor(ctx), enabled ? "client_enabled" : "client_disabled", clientId);
        return TypedResults.NoContent();
    }

    private static string Actor(HttpContext ctx) => ctx.Items[ActorKey] as string ?? "unknown";

    private const string ActorKey = "addaccion.admin.actor";

    private static async ValueTask<object?> RequireAdminAsync(EndpointFilterInvocationContext invocation, EndpointFilterDelegate next)
    {
        var ctx = invocation.HttpContext;
        var token = FormReader.BearerToken(ctx);
        if (token is null)
            return OAuthResults.BearerError(ctx, OAuthErrors.InvalidToken, "Bearer token required.", StatusCodes.Status401Unauthorized);

        var validator = ctx.RequestServices.GetRequiredService<AccessTokenValidator>();
        var at = await validator.ValidateAsync(token, checkRevocation: true, ctx.RequestAborted).ConfigureAwait(false);
        if (at is null)
            return OAuthResults.BearerError(ctx, OAuthErrors.InvalidToken, "The access token is invalid or expired.", StatusCodes.Status401Unauthorized);
        if (!at.Audiences.Contains(ClientRegistration.AdminAudience, StringComparer.Ordinal) || !ScopeParser.Contains(at.Scopes, ClientRegistration.AdminScope))
            return OAuthResults.BearerError(ctx, OAuthErrors.InsufficientScope, "auth.admin scope required.", StatusCodes.Status403Forbidden);

        ctx.Items[ActorKey] = at.Subject;
        return await next(invocation).ConfigureAwait(false);
    }
}
