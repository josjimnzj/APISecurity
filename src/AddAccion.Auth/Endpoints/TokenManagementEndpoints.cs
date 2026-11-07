using System.Text.Json;
using AddAccion.Auth.Configuration;
using AddAccion.Auth.Crypto;
using AddAccion.Auth.Hosting;
using AddAccion.Auth.Persistence;
using AddAccion.Auth.Protocol;
using AddAccion.Auth.Security;
using Microsoft.Extensions.Options;

namespace AddAccion.Auth.Endpoints;

/// <summary>RFC 7662 introspection and RFC 7009 revocation.</summary>
public sealed class TokenManagementEndpoints(
    ClientAuthenticator authenticator,
    AccessTokenValidator validator,
    IGrantStore grants,
    AuthMetrics metrics,
    IOptions<AuthServerOptions> options,
    TimeProvider time,
    ILogger<TokenManagementEndpoints> logger)
{
    private readonly string _issuer = options.Value.Issuer;

    public async Task<IResult> IntrospectAsync(HttpContext ctx)
    {
        var ct = ctx.RequestAborted;
        var (p, formError) = await FormReader.ReadAsync(ctx).ConfigureAwait(false);
        if (p is null) return OAuthResults.Error(ctx, OAuthErrors.InvalidRequest, formError);

        var auth = await authenticator.AuthenticateAsync(ctx, p, _issuer + Routes.Introspect, ct).ConfigureAwait(false);
        if (!auth.Succeeded || !auth.Client!.IsConfidential)
        {
            if (auth.UsedBasic) ctx.Response.Headers.WWWAuthenticate = "Basic realm=\"addaccion-auth\"";
            return OAuthResults.Error(ctx, OAuthErrors.InvalidClient, "Client authentication failed.", StatusCodes.Status401Unauthorized);
        }
        var caller = auth.Client;
        if (!caller.CanIntrospect)
            return OAuthResults.Error(ctx, OAuthErrors.UnauthorizedClient, "Client is not allowed to introspect tokens.", StatusCodes.Status403Forbidden);

        var token = p["token"];
        if (token is null) return OAuthResults.Error(ctx, OAuthErrors.InvalidRequest, "token is required.");

        metrics.Introspection();
        if (AccessTokenValidator.LooksLikeJwt(token))
        {
            var at = await validator.ValidateAsync(token, checkRevocation: true, ct).ConfigureAwait(false);
            if (at is null) return Inactive(ctx);
            return OAuthResults.Json(ctx, new IntrospectionResponse
            {
                Active = true,
                Scope = ScopeParser.Join(at.Scopes),
                ClientId = at.ClientId,
                TokenType = "Bearer",
                Exp = at.ExpiresAt.ToUnixTimeSeconds(),
                Iat = at.IssuedAt.ToUnixTimeSeconds(),
                Sub = at.Subject,
                Aud = at.Audiences,
                Iss = _issuer,
                Jti = at.Jti,
                Roles = at.Roles.Count > 0 ? at.Roles : null,
            }, AuthJsonContext.Default.IntrospectionResponse);
        }

        if (token.Length > 128) return Inactive(ctx);
        var rt = await grants.FindRefreshTokenAsync(TokenHasher.Hash(token), ct).ConfigureAwait(false);
        // Refresh tokens are only disclosed to the client they were issued to.
        if (rt is null || rt.RevokedAt is not null || rt.ConsumedAt is not null || rt.ExpiresAt <= time.GetUtcNow()
            || !string.Equals(rt.ClientId, caller.ClientId, StringComparison.Ordinal))
        {
            return Inactive(ctx);
        }
        return OAuthResults.Json(ctx, new IntrospectionResponse
        {
            Active = true,
            Scope = rt.Scopes,
            ClientId = rt.ClientId,
            Exp = rt.ExpiresAt.ToUnixTimeSeconds(),
            Iat = rt.CreatedAt.ToUnixTimeSeconds(),
            Sub = rt.UserId,
            Iss = _issuer,
        }, AuthJsonContext.Default.IntrospectionResponse);
    }

    private static IResult Inactive(HttpContext ctx) =>
        OAuthResults.Json(ctx, IntrospectionResponse.Inactive, AuthJsonContext.Default.IntrospectionResponse);

    public async Task<IResult> RevokeAsync(HttpContext ctx)
    {
        var ct = ctx.RequestAborted;
        var (p, formError) = await FormReader.ReadAsync(ctx).ConfigureAwait(false);
        if (p is null) return OAuthResults.Error(ctx, OAuthErrors.InvalidRequest, formError);

        var auth = await authenticator.AuthenticateAsync(ctx, p, _issuer + Routes.Revoke, ct).ConfigureAwait(false);
        if (!auth.Succeeded)
        {
            if (auth.UsedBasic) ctx.Response.Headers.WWWAuthenticate = "Basic realm=\"addaccion-auth\"";
            return OAuthResults.Error(ctx, auth.Error!, auth.Description);
        }
        var caller = auth.Client!;

        var token = p["token"];
        if (token is null) return OAuthResults.Error(ctx, OAuthErrors.InvalidRequest, "token is required.");

        var now = time.GetUtcNow();
        if (AccessTokenValidator.LooksLikeJwt(token))
        {
            var at = await validator.ValidateAsync(token, checkRevocation: false, ct).ConfigureAwait(false);
            if (at is not null && string.Equals(at.ClientId, caller.ClientId, StringComparison.Ordinal))
            {
                await grants.RevokeAccessTokenAsync(at.Jti, at.ExpiresAt, ct).ConfigureAwait(false);
                Log.TokenRevoked(logger, "access_token", caller.ClientId);
            }
        }
        else if (token.Length <= 128)
        {
            var rt = await grants.FindRefreshTokenAsync(TokenHasher.Hash(token), ct).ConfigureAwait(false);
            if (rt is not null && string.Equals(rt.ClientId, caller.ClientId, StringComparison.Ordinal))
            {
                await grants.RevokeRefreshTokenFamilyAsync(rt.FamilyId, now, ct).ConfigureAwait(false);
                Log.TokenRevoked(logger, "refresh_token", caller.ClientId);
            }
        }

        // RFC 7009 §2.2: 200 whether or not the token was valid (no token oracle).
        OAuthResults.NoStore(ctx);
        return TypedResults.Ok();
    }
}

/// <summary>OIDC UserInfo (GET/POST, Bearer token with scope openid).</summary>
public sealed class UserInfoEndpoint(AccessTokenValidator validator, IUserStore users)
{
    public async Task<IResult> HandleAsync(HttpContext ctx)
    {
        var token = FormReader.BearerToken(ctx);
        if (token is null)
        {
            ctx.Response.Headers.WWWAuthenticate = "Bearer realm=\"addaccion-auth\"";
            OAuthResults.NoStore(ctx);
            return TypedResults.Unauthorized();
        }

        var at = await validator.ValidateAsync(token, checkRevocation: true, ctx.RequestAborted).ConfigureAwait(false);
        if (at is null) return OAuthResults.BearerError(ctx, OAuthErrors.InvalidToken, "The access token is invalid or expired.", StatusCodes.Status401Unauthorized);
        if (!ScopeParser.Contains(at.Scopes, StandardScopes.OpenId))
            return OAuthResults.BearerError(ctx, OAuthErrors.InsufficientScope, "The openid scope is required.", StatusCodes.Status403Forbidden);

        var user = await users.FindByIdAsync(at.Subject, ctx.RequestAborted).ConfigureAwait(false);
        if (user is null || !user.IsActive)
            return OAuthResults.BearerError(ctx, OAuthErrors.InvalidToken, "The user is not active.", StatusCodes.Status401Unauthorized);

        var claims = new Dictionary<string, object>(StringComparer.Ordinal) { ["sub"] = user.UserId };
        UserClaims.AddTo(claims, user, at.Scopes);

        OAuthResults.NoStore(ctx);
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer))
        {
            w.WriteStartObject();
            foreach (var (name, value) in claims)
            {
                switch (value)
                {
                    case string s: w.WriteString(name, s); break;
                    case bool b: w.WriteBoolean(name, b); break;
                    case string[] arr:
                        w.WriteStartArray(name);
                        foreach (var item in arr) w.WriteStringValue(item);
                        w.WriteEndArray();
                        break;
                }
            }
            w.WriteEndObject();
        }
        return TypedResults.Bytes(buffer.ToArray(), "application/json");
    }
}
