using AddAccion.Auth.Configuration;
using AddAccion.Auth.Crypto;
using AddAccion.Auth.Domain;
using AddAccion.Auth.Hosting;
using AddAccion.Auth.Persistence;
using AddAccion.Auth.Protocol;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.Options;

namespace AddAccion.Auth.Endpoints;

public sealed record AuthorizeRequest(
    ClientApplication Client,
    string RedirectUri,
    IReadOnlyList<string> Scopes,
    string? State,
    string CodeChallenge,
    string? Nonce);

/// <summary>
/// GET/POST /oauth2/authorize — authorization code flow with mandatory PKCE (S256) and a server-rendered
/// login form for AddACCION users. Errors that cannot be trusted to the redirect URI (unknown client,
/// unregistered redirect_uri) are shown locally and never redirected (RFC 6749 §4.1.2.1).
/// </summary>
public sealed class AuthorizeEndpoint(
    ClientCatalog clients,
    ScopeCatalog scopes,
    IUserStore users,
    IGrantStore grants,
    IPasswordHashVerifier passwords,
    PasswordVerificationGate gate,
    CsrfProtector csrf,
    AuthMetrics metrics,
    IOptions<AuthServerOptions> options,
    TimeProvider time,
    ILogger<AuthorizeEndpoint> logger)
{
    public const int MaxLoginLength = 256;
    public const int MaxPasswordLength = 1024;

    private readonly AuthServerOptions _options = options.Value;
    private readonly string _issuerOrigin = new Uri(options.Value.Issuer).GetLeftPart(UriPartial.Authority);

    private string CsrfCookieName => _options.RequireHttps ? "__Host-aa_csrf" : "aa_csrf";

    public async Task<IResult> GetAsync(HttpContext ctx)
    {
        var p = RequestParameters.FromQuery(ctx.Request.Query);
        var (request, failure) = await ValidateAsync(p, ctx.RequestAborted).ConfigureAwait(false);
        if (failure is not null) return failure;
        return LoginForm(ctx, request!, p, loginName: null, errorMessage: null, StatusCodes.Status200OK);
    }

    public async Task<IResult> PostAsync(HttpContext ctx)
    {
        var ct = ctx.RequestAborted;
        if (!IsSameOriginPost(ctx))
            return LoginPage.Error("Solicitud no permitida.", StatusCodes.Status403Forbidden);

        var (p, formError) = await FormReader.ReadAsync(ctx).ConfigureAwait(false);
        if (p is null) return LoginPage.Error(formError ?? "Solicitud no válida.", StatusCodes.Status400BadRequest);

        var (request, failure) = await ValidateAsync(p, ct).ConfigureAwait(false);
        if (failure is not null) return failure;

        var login = p["username"]?.Trim();
        var password = p["password"];

        if (!csrf.Validate(ctx.Request.Cookies[CsrfCookieName], p["csrf_token"]))
        {
            // Missing/expired cookie: show the form again with a fresh token; no credential is evaluated.
            return LoginForm(ctx, request!, p, login, "Por seguridad, vuelva a introducir sus credenciales.", StatusCodes.Status400BadRequest);
        }

        if (string.IsNullOrEmpty(login) || string.IsNullOrEmpty(password) || login.Length > MaxLoginLength || password.Length > MaxPasswordLength)
            return LoginForm(ctx, request!, p, login, "Introduzca usuario y contraseña.", StatusCodes.Status400BadRequest);

        var now = time.GetUtcNow();
        var user = await users.FindByLoginAsync(login, ct).ConfigureAwait(false);

        var locked = user?.LockoutEnd is { } end && end > now;
        PasswordCheck check;
        // The gate only covers the CPU-bound PBKDF2 work, never database I/O.
        using (var slot = await gate.TryEnterAsync(ct).ConfigureAwait(false))
        {
            if (slot is null)
                return LoginPage.Error("El servicio está ocupado. Inténtelo de nuevo en unos segundos.", StatusCodes.Status503ServiceUnavailable);

            if (user is null || !user.IsActive || locked)
            {
                // Same CPU cost whatever the reason (no user enumeration by timing, OWASP ASVS V2.2).
                passwords.VerifyDummy(password);
                check = PasswordCheck.Failed;
            }
            else
            {
                check = passwords.Verify(user.PasswordHash, password);
            }
        }

        if (user is null || !user.IsActive || locked)
        {
            metrics.LoginFailed(user is null ? "unknown_user" : locked ? "locked" : "inactive");
            if (user is null) Log.LoginFailedUnknownUser(logger, LogRedaction.Fingerprint(login));
            else Log.LoginFailed(logger, user.UserId, locked ? "locked" : "inactive");
            return LoginForm(ctx, request!, p, login, LoginPage.InvalidCredentials, StatusCodes.Status400BadRequest);
        }

        if (check == PasswordCheck.Failed)
        {
            var lockoutEnd = await users.RecordFailedLoginAsync(user.UserId, now, _options.Login.MaxFailedAttempts,
                TimeSpan.FromSeconds(_options.Login.LockoutSeconds), ct).ConfigureAwait(false);
            metrics.LoginFailed("bad_password");
            Log.LoginFailed(logger, user.UserId, lockoutEnd is null ? "bad_password" : "bad_password_now_locked");
            return LoginForm(ctx, request!, p, login, LoginPage.InvalidCredentials, StatusCodes.Status400BadRequest);
        }
        if (check == PasswordCheck.SuccessWeakHash) Log.WeakPasswordHash(logger, user.UserId);

        await users.RecordSuccessfulLoginAsync(user.UserId, now, ct).ConfigureAwait(false);

        var code = RandomTokens.Create(32);
        await grants.CreateAuthorizationCodeAsync(new AuthorizationCodeRecord
        {
            CodeHash = TokenHasher.Hash(code),
            ClientId = request!.Client.ClientId,
            UserId = user.UserId,
            RedirectUri = request.RedirectUri,
            Scopes = ScopeParser.Join(request.Scopes),
            CodeChallenge = request.CodeChallenge,
            Nonce = request.Nonce,
            AuthTime = now,
            CreatedAt = now,
            ExpiresAt = now.AddSeconds(_options.Tokens.AuthorizationCodeLifetimeSeconds),
        }, ct).ConfigureAwait(false);

        metrics.LoginSucceeded();
        Log.LoginSucceeded(logger, user.UserId, request.Client.ClientId);

        OAuthResults.NoStore(ctx);
        // 303 so the browser follows with GET (the password must never be re-posted).
        var location = RedirectUris.AppendQuery(request.RedirectUri,
            [new("code", code), new("state", request.State), new("iss", _options.Issuer)]);
        ctx.Response.Headers.Location = location;
        return TypedResults.StatusCode(StatusCodes.Status303SeeOther);
    }

    private async Task<(AuthorizeRequest? Request, IResult? Failure)> ValidateAsync(RequestParameters p, CancellationToken ct)
    {
        if (p.DuplicateParameter is not null)
            return (null, LocalError("La solicitud de autorización contiene parámetros repetidos."));

        var clientId = p["client_id"];
        var client = clientId is null ? null : await clients.FindAsync(clientId, ct).ConfigureAwait(false);
        if (client is null || !client.IsEnabled)
            return (null, LocalError("La aplicación que solicita el acceso no está registrada o está deshabilitada."));

        var redirectUri = p["redirect_uri"];
        if (redirectUri is null || !RedirectUris.Matches(client.RedirectUris, redirectUri))
            return (null, LocalError("La dirección de retorno (redirect_uri) no está registrada para esta aplicación."));

        var state = p["state"];
        if (state is { Length: > 1024 })
            return (null, LocalError("El parámetro state es demasiado largo."));

        IResult Redirect(string error, string description) => RedirectError(redirectUri, state, error, description);

        if (p["request"] is not null) return (null, Redirect(OAuthErrors.RequestNotSupported, "Request objects are not supported."));
        if (p["request_uri"] is not null) return (null, Redirect(OAuthErrors.RequestUriNotSupported, "request_uri is not supported."));
        if (p["response_type"] != "code") return (null, Redirect(OAuthErrors.UnsupportedResponseType, "Only response_type=code is supported."));
        if (p["response_mode"] is { } mode && mode != "query") return (null, Redirect(OAuthErrors.InvalidRequest, "Only response_mode=query is supported."));
        if (!client.AllowsGrant(GrantTypes.AuthorizationCode))
            return (null, Redirect(OAuthErrors.UnauthorizedClient, "Client is not allowed to use the authorization code flow."));

        var challenge = p["code_challenge"];
        if (challenge is null) return (null, Redirect(OAuthErrors.InvalidRequest, "PKCE code_challenge is required."));
        if (p["code_challenge_method"] != "S256") return (null, Redirect(OAuthErrors.InvalidRequest, "code_challenge_method must be S256."));
        if (!Pkce.IsValidS256Challenge(challenge)) return (null, Redirect(OAuthErrors.InvalidRequest, "Malformed code_challenge."));

        if (!ScopeParser.TryParse(p["scope"], out var requested) || requested.Count == 0)
            return (null, Redirect(OAuthErrors.InvalidScope, "A valid scope is required."));
        var catalog = await scopes.GetAsync(ct).ConfigureAwait(false);
        foreach (var s in requested)
        {
            if (!catalog.IsKnown(s) || !client.AllowsScope(s))
                return (null, Redirect(OAuthErrors.InvalidScope, "A requested scope is not allowed for this client."));
        }

        var nonce = p["nonce"];
        if (nonce is { Length: > 512 }) return (null, Redirect(OAuthErrors.InvalidRequest, "nonce is too long."));

        // No SSO session is kept in v1: silent authentication is impossible.
        if (p["prompt"] is { } prompt && prompt.Split(' ').Contains("none"))
            return (null, Redirect(OAuthErrors.LoginRequired, "User interaction is required."));

        return (new AuthorizeRequest(client, redirectUri, requested, state, challenge, nonce), null);
    }

    private RedirectHttpResult RedirectError(string redirectUri, string? state, string error, string description)
    {
        metrics.AuthorizeFailed(error);
        var location = RedirectUris.AppendQuery(redirectUri,
            [new("error", error), new("error_description", description), new("state", state), new("iss", _options.Issuer)]);
        return TypedResults.Redirect(location);
    }

    private IResult LocalError(string message)
    {
        metrics.AuthorizeFailed("invalid_client_or_redirect");
        return LoginPage.Error(message, StatusCodes.Status400BadRequest);
    }

    private IResult LoginForm(HttpContext ctx, AuthorizeRequest request, RequestParameters p, string? loginName, string? errorMessage, int status)
    {
        var cookie = ctx.Request.Cookies[CsrfCookieName];
        if (string.IsNullOrEmpty(cookie) || cookie.Length > 100)
        {
            cookie = CsrfProtector.NewCookieValue();
            ctx.Response.Cookies.Append(CsrfCookieName, cookie, new CookieOptions
            {
                HttpOnly = true,
                Secure = _options.RequireHttps,
                SameSite = SameSiteMode.Lax,
                Path = "/",
                IsEssential = true,
            });
        }

        var hidden = new List<KeyValuePair<string, string>>();
        foreach (var name in LoginPage.ForwardedParameters)
        {
            if (p[name] is { } value) hidden.Add(new(name, value));
        }
        hidden.Add(new("csrf_token", csrf.TokenFor(cookie)));

        var model = new LoginPage.Model(
            _options.Login.BrandName,
            request.Client.ClientName,
            hidden,
            loginName,
            errorMessage,
            RedirectUris.HttpOrigin(request.RedirectUri) ?? SchemeSource(request.RedirectUri));
        return LoginPage.Form(model, status);
    }

    private static string? SchemeSource(string uri) =>
        Uri.TryCreate(uri, UriKind.Absolute, out var u) ? u.Scheme + ":" : null;

    /// <summary>Defense in depth on top of the CSRF token: reject cross-origin form posts when the browser tells us.</summary>
    private bool IsSameOriginPost(HttpContext ctx)
    {
        var origin = ctx.Request.Headers.Origin.ToString();
        if (!string.IsNullOrEmpty(origin)) return string.Equals(origin, _issuerOrigin, StringComparison.OrdinalIgnoreCase);
        var site = ctx.Request.Headers["Sec-Fetch-Site"].ToString();
        return string.IsNullOrEmpty(site) || site is "same-origin" or "none";
    }
}
