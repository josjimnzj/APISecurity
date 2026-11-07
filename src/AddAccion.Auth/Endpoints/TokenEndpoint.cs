using AddAccion.Auth.Configuration;
using AddAccion.Auth.Crypto;
using AddAccion.Auth.Domain;
using AddAccion.Auth.Hosting;
using AddAccion.Auth.Persistence;
using AddAccion.Auth.Protocol;
using AddAccion.Auth.Security;
using Microsoft.Extensions.Options;

namespace AddAccion.Auth.Endpoints;

/// <summary>POST /oauth2/token — client_credentials, authorization_code (PKCE S256) and refresh_token (rotation + reuse detection).</summary>
public sealed class TokenEndpoint(
    ClientAuthenticator authenticator,
    ScopeCatalog scopes,
    IGrantStore grants,
    IUserStore users,
    TokenService tokens,
    AuthMetrics metrics,
    IOptions<AuthServerOptions> options,
    TimeProvider time,
    ILogger<TokenEndpoint> logger)
{
    private readonly string _issuer = options.Value.Issuer;
    private string Endpoint => _issuer + Routes.Token;

    public async Task<IResult> HandleAsync(HttpContext ctx)
    {
        var ct = ctx.RequestAborted;
        var (p, formError) = await FormReader.ReadAsync(ctx).ConfigureAwait(false);
        if (p is null) return Fail(ctx, "unknown", OAuthErrors.InvalidRequest, formError);

        var grantType = p["grant_type"];
        if (grantType is null) return Fail(ctx, "unknown", OAuthErrors.InvalidRequest, "grant_type is required.");

        var auth = await authenticator.AuthenticateAsync(ctx, p, Endpoint, ct).ConfigureAwait(false);
        if (!auth.Succeeded)
        {
            if (auth.UsedBasic) ctx.Response.Headers.WWWAuthenticate = "Basic realm=\"addaccion-auth\", charset=\"UTF-8\"";
            return Fail(ctx, grantType, auth.Error!, auth.Description);
        }

        var client = auth.Client!;
        return grantType switch
        {
            GrantTypes.ClientCredentials => await ClientCredentialsAsync(ctx, client, p, ct).ConfigureAwait(false),
            GrantTypes.AuthorizationCode => await AuthorizationCodeAsync(ctx, client, p, ct).ConfigureAwait(false),
            GrantTypes.RefreshToken => await RefreshTokenAsync(ctx, client, p, ct).ConfigureAwait(false),
            _ => Fail(ctx, "unknown", OAuthErrors.UnsupportedGrantType, null),
        };
    }

    private async Task<IResult> ClientCredentialsAsync(HttpContext ctx, ClientApplication client, RequestParameters p, CancellationToken ct)
    {
        const string grant = GrantTypes.ClientCredentials;
        if (!client.IsConfidential || !client.AllowsGrant(grant))
            return Fail(ctx, grant, OAuthErrors.UnauthorizedClient, "Client is not allowed to use client_credentials.");

        if (!ScopeParser.TryParse(p["scope"], out var requested))
            return Fail(ctx, grant, OAuthErrors.InvalidScope, "Malformed scope.");

        var catalog = await scopes.GetAsync(ct).ConfigureAwait(false);
        IReadOnlyList<string> granted;
        if (requested.Count == 0)
        {
            granted = client.AllowedScopes.Where(catalog.IsApiScope).ToArray();
        }
        else
        {
            foreach (var s in requested)
            {
                if (!catalog.IsApiScope(s) || !client.AllowsScope(s))
                    return Fail(ctx, grant, OAuthErrors.InvalidScope, "A requested scope is not allowed for this client.");
            }
            granted = requested;
        }
        if (granted.Count == 0) return Fail(ctx, grant, OAuthErrors.InvalidScope, "No scope could be granted.");

        var now = time.GetUtcNow();
        var spec = new AccessTokenSpec
        {
            Subject = client.ClientId,
            ClientId = client.ClientId,
            Scopes = granted,
            Audiences = catalog.AudiencesFor(granted),
            IssuedAt = now,
            ExpiresAt = now.AddSeconds(client.AccessTokenLifetimeSeconds),
            Jti = TokenService.NewJti(),
        };
        var accessToken = tokens.CreateAccessToken(spec);
        metrics.TokenIssued(grant);
        Log.TokenIssued(logger, grant, client.ClientId, spec.Subject, spec.Jti);

        return OAuthResults.Json(ctx, new TokenResponse
        {
            AccessToken = accessToken,
            ExpiresIn = client.AccessTokenLifetimeSeconds,
            Scope = ScopeParser.Join(granted),
        }, AuthJsonContext.Default.TokenResponse);
    }

    private async Task<IResult> AuthorizationCodeAsync(HttpContext ctx, ClientApplication client, RequestParameters p, CancellationToken ct)
    {
        const string grant = GrantTypes.AuthorizationCode;
        if (!client.AllowsGrant(grant))
            return Fail(ctx, grant, OAuthErrors.UnauthorizedClient, "Client is not allowed to use authorization_code.");

        var code = p["code"];
        var redirectUri = p["redirect_uri"];
        var verifier = p["code_verifier"];
        if (code is null || redirectUri is null || verifier is null)
            return Fail(ctx, grant, OAuthErrors.InvalidRequest, "code, redirect_uri and code_verifier are required.");
        if (!Pkce.IsValidVerifier(verifier))
            return Fail(ctx, grant, OAuthErrors.InvalidRequest, "Malformed code_verifier.");
        if (code.Length > 128)
            return Fail(ctx, grant, OAuthErrors.InvalidGrant, "Invalid authorization code.");

        var now = time.GetUtcNow();
        var jti = TokenService.NewJti();
        var familyId = Guid.NewGuid();
        var accessExpires = now.AddSeconds(client.AccessTokenLifetimeSeconds);
        var redemption = new CodeRedemption(TokenHasher.Hash(code), client.ClientId, redirectUri, Pkce.S256(verifier), now, familyId, jti, accessExpires);

        var result = await grants.RedeemAuthorizationCodeAsync(redemption, ct).ConfigureAwait(false);
        if (result.Status == CodeRedemptionStatus.Replayed)
        {
            // RFC 6749 §4.1.2 / RFC 9700 §4.5: a reused code means it leaked; revoke what it produced.
            var replayed = result.Code!;
            if (replayed.RefreshFamilyId is { } fam) await grants.RevokeRefreshTokenFamilyAsync(fam, now, ct).ConfigureAwait(false);
            if (replayed.AccessTokenJti is { } j && replayed.AccessTokenExpiresAt is { } exp)
                await grants.RevokeAccessTokenAsync(j, exp, ct).ConfigureAwait(false);
            metrics.SecurityEvent("authorization_code_replay");
            Log.CodeReplay(logger, client.ClientId);
            return Fail(ctx, grant, OAuthErrors.InvalidGrant, "Invalid authorization code.");
        }
        if (result.Status != CodeRedemptionStatus.Redeemed)
            return Fail(ctx, grant, OAuthErrors.InvalidGrant, "Invalid authorization code.");

        var record = result.Code!;
        var user = await users.FindByIdAsync(record.UserId, ct).ConfigureAwait(false);
        if (user is null || !user.IsActive)
            return Fail(ctx, grant, OAuthErrors.InvalidGrant, "The user is not active.");

        _ = ScopeParser.TryParse(record.Scopes, out var granted);
        return await IssueUserTokensAsync(ctx, grant, client, user, granted, record.AuthTime, record.Nonce, now, jti, accessExpires,
            familyId, refreshExpires: now.AddSeconds(client.RefreshTokenLifetimeSeconds), ct).ConfigureAwait(false);
    }

    private async Task<IResult> RefreshTokenAsync(HttpContext ctx, ClientApplication client, RequestParameters p, CancellationToken ct)
    {
        const string grant = GrantTypes.RefreshToken;
        if (!client.AllowsGrant(grant))
            return Fail(ctx, grant, OAuthErrors.UnauthorizedClient, "Client is not allowed to use refresh_token.");

        var presented = p["refresh_token"];
        if (presented is null) return Fail(ctx, grant, OAuthErrors.InvalidRequest, "refresh_token is required.");
        if (presented.Length > 128) return Fail(ctx, grant, OAuthErrors.InvalidGrant, "Invalid refresh token.");

        var now = time.GetUtcNow();
        var record = await grants.FindRefreshTokenAsync(TokenHasher.Hash(presented), ct).ConfigureAwait(false);
        if (record is null) return Fail(ctx, grant, OAuthErrors.InvalidGrant, "Invalid refresh token.");

        if (!string.Equals(record.ClientId, client.ClientId, StringComparison.Ordinal))
        {
            // Token presented by another client: treat as stolen.
            await RevokeFamilyAsync(record, now, "refresh_token_wrong_client", ct).ConfigureAwait(false);
            return Fail(ctx, grant, OAuthErrors.InvalidGrant, "Invalid refresh token.");
        }
        if (record.RevokedAt is not null || record.ExpiresAt <= now)
            return Fail(ctx, grant, OAuthErrors.InvalidGrant, "Invalid refresh token.");
        if (record.ConsumedAt is not null)
        {
            // Rotation reuse detection (RFC 9700 §4.14.2): the whole family is revoked.
            await RevokeFamilyAsync(record, now, "refresh_token_reuse", ct).ConfigureAwait(false);
            return Fail(ctx, grant, OAuthErrors.InvalidGrant, "Invalid refresh token.");
        }

        _ = ScopeParser.TryParse(record.Scopes, out var original);
        IReadOnlyList<string> granted = original;
        if (p["scope"] is { } scopeParam)
        {
            if (!ScopeParser.TryParse(scopeParam, out var requested) || requested.Count == 0)
                return Fail(ctx, grant, OAuthErrors.InvalidScope, "Malformed scope.");
            foreach (var s in requested)
            {
                if (!ScopeParser.Contains(original, s))
                    return Fail(ctx, grant, OAuthErrors.InvalidScope, "Requested scope exceeds the original grant.");
            }
            granted = requested;
        }

        var user = await users.FindByIdAsync(record.UserId, ct).ConfigureAwait(false);
        if (user is null || !user.IsActive)
        {
            await grants.RevokeRefreshTokenFamilyAsync(record.FamilyId, now, ct).ConfigureAwait(false);
            return Fail(ctx, grant, OAuthErrors.InvalidGrant, "The user is not active.");
        }

        return await IssueUserTokensAsync(ctx, grant, client, user, granted, record.AuthTime, nonce: null, now, TokenService.NewJti(),
            now.AddSeconds(client.AccessTokenLifetimeSeconds), record.FamilyId, record.ExpiresAt, ct, rotateFrom: record).ConfigureAwait(false);
    }

    private async Task<IResult> IssueUserTokensAsync(
        HttpContext ctx, string grant, ClientApplication client, UserAccount user, IReadOnlyList<string> granted,
        DateTimeOffset authTime, string? nonce, DateTimeOffset now, string jti, DateTimeOffset accessExpires,
        Guid familyId, DateTimeOffset refreshExpires, CancellationToken ct, RefreshTokenRecord? rotateFrom = null)
    {
        string? refreshToken = null;
        if (client.AllowsGrant(GrantTypes.RefreshToken))
        {
            refreshToken = RandomTokens.Create(32);
            var next = new RefreshTokenRecord
            {
                TokenHash = TokenHasher.Hash(refreshToken),
                FamilyId = familyId,
                ClientId = client.ClientId,
                UserId = user.UserId,
                // The refresh token keeps the original grant even if this access token was down-scoped.
                Scopes = rotateFrom?.Scopes ?? ScopeParser.Join(granted),
                AuthTime = authTime,
                CreatedAt = now,
                ExpiresAt = refreshExpires,
            };
            if (rotateFrom is null)
            {
                await grants.CreateRefreshTokenAsync(next, ct).ConfigureAwait(false);
            }
            else if (!await grants.RotateRefreshTokenAsync(rotateFrom.Id, next, now, ct).ConfigureAwait(false))
            {
                // Lost a race against another use of the same token: that is reuse.
                await RevokeFamilyAsync(rotateFrom, now, "refresh_token_reuse", ct).ConfigureAwait(false);
                return Fail(ctx, grant, OAuthErrors.InvalidGrant, "Invalid refresh token.");
            }
        }

        var catalog = await scopes.GetAsync(ct).ConfigureAwait(false);
        var accessToken = tokens.CreateAccessToken(new AccessTokenSpec
        {
            Subject = user.UserId,
            ClientId = client.ClientId,
            Scopes = granted,
            Audiences = catalog.AudiencesFor(granted),
            IssuedAt = now,
            ExpiresAt = accessExpires,
            Jti = jti,
            AuthTime = authTime,
            Roles = ScopeParser.Contains(granted, StandardScopes.Roles) ? user.Roles : null,
        });

        string? idToken = ScopeParser.Contains(granted, StandardScopes.OpenId)
            ? tokens.CreateIdToken(user, client.ClientId, granted, nonce, authTime, now, accessToken)
            : null;

        metrics.TokenIssued(grant);
        Log.TokenIssued(logger, grant, client.ClientId, user.UserId, jti);

        return OAuthResults.Json(ctx, new TokenResponse
        {
            AccessToken = accessToken,
            ExpiresIn = (int)(accessExpires - now).TotalSeconds,
            Scope = ScopeParser.Join(granted),
            RefreshToken = refreshToken,
            IdToken = idToken,
        }, AuthJsonContext.Default.TokenResponse);
    }

    private async Task RevokeFamilyAsync(RefreshTokenRecord record, DateTimeOffset now, string reason, CancellationToken ct)
    {
        var revoked = await grants.RevokeRefreshTokenFamilyAsync(record.FamilyId, now, ct).ConfigureAwait(false);
        metrics.SecurityEvent(reason);
        Log.RefreshFamilyRevoked(logger, reason, record.ClientId, record.UserId, revoked);
    }

    private IResult Fail(HttpContext ctx, string grant, string error, string? description)
    {
        metrics.TokenFailed(grant, error);
        return OAuthResults.Error(ctx, error, description);
    }
}
