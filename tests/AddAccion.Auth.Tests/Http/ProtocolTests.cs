using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using AddAccion.Auth.Domain;
using AddAccion.Auth.Tests.Infrastructure;
using Microsoft.IdentityModel.Tokens;

namespace AddAccion.Auth.Tests.Http;

/// <summary>
/// Black-box conformance suite (HTTP only). Runs against every fixture: in-memory, SQL Server and an external
/// process (Native AOT binary / future Go implementation).
/// </summary>
public abstract class ProtocolTests<TFixture>(TFixture fixture) : IClassFixture<TFixture>
    where TFixture : AuthServerFixture
{
    protected TFixture Fixture { get; } = fixture;

    protected OAuthTestClient NewClient()
    {
        Fixture.SkipIfUnavailable();
        return new OAuthTestClient(Fixture);
    }

    // ------------------------------------------------------------------ metadata

    [Fact]
    public async Task Discovery_advertises_endpoints_and_only_safe_options()
    {
        using var c = NewClient();
        var response = await c.Http.GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var doc = await OAuthTestClient.JsonAsync(response);
        var issuer = Fixture.Issuer;
        Assert.Equal(issuer, doc.GetProperty("issuer").GetString());
        Assert.Equal(issuer + "/oauth2/token", doc.GetProperty("token_endpoint").GetString());
        Assert.Equal(issuer + "/.well-known/jwks.json", doc.GetProperty("jwks_uri").GetString());
        Assert.Equal(["S256"], doc.GetProperty("code_challenge_methods_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(["code"], doc.GetProperty("response_types_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.DoesNotContain("password", doc.GetProperty("grant_types_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.True(doc.GetProperty("authorization_response_iss_parameter_supported").GetBoolean());

        var metadata = await OAuthTestClient.JsonAsync(await c.Http.GetAsync("/.well-known/oauth-authorization-server"));
        Assert.Equal(issuer, metadata.GetProperty("issuer").GetString());
    }

    [Fact]
    public async Task Jwks_publishes_public_keys_only_with_thumbprint_kid()
    {
        using var c = NewClient();
        var json = await c.Http.GetStringAsync("/.well-known/jwks.json");
        var set = new JsonWebKeySet(json);
        Assert.NotEmpty(set.Keys);
        foreach (var key in set.Keys)
        {
            Assert.True(string.IsNullOrEmpty(key.D), "private key material published");
            Assert.Equal(Base64UrlEncoder.Encode(key.ComputeJwkThumbprint()), key.Kid);
            Assert.Equal("sig", key.Use);
        }
    }

    // ------------------------------------------------------------------ client credentials

    [Fact]
    public async Task ClientCredentials_basic_issues_rfc9068_jwt()
    {
        using var c = NewClient();
        var (client, secret) = await c.ConfidentialClientAsync(scopes: ["erp.read", "crm.read"]);

        var response = await c.ClientCredentialsAsync(client.ClientId, secret, "erp.read");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("no-store", response.Headers.CacheControl!.ToString());
        var body = await OAuthTestClient.JsonAsync(response);
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
        Assert.Equal("erp.read", body.GetProperty("scope").GetString());
        Assert.Equal(600, body.GetProperty("expires_in").GetInt32());
        Assert.False(body.TryGetProperty("refresh_token", out _));

        var jwt = await c.ValidateWithJwksAsync(body.GetProperty("access_token").GetString()!, AuthServerFixture.AudienceOf("erp.read"));
        Assert.Equal(client.ClientId, jwt.Subject);
        Assert.Equal(client.ClientId, jwt.GetPayloadValue<string>("client_id"));
        Assert.Equal("erp.read", jwt.GetPayloadValue<string>("scope"));
        Assert.False(string.IsNullOrEmpty(jwt.Id));
    }

    [Fact]
    public async Task ClientCredentials_without_scope_grants_all_allowed_api_scopes_with_all_audiences()
    {
        using var c = NewClient();
        var (client, secret) = await c.ConfidentialClientAsync(scopes: ["erp.read", "crm.read"]);
        var body = await OAuthTestClient.JsonAsync(await c.ClientCredentialsAsync(client.ClientId, secret));
        Assert.Equal(["crm.read", "erp.read"], body.GetProperty("scope").GetString()!.Split(' ').Order());
        var jwt = await c.ValidateWithJwksAsync(body.GetProperty("access_token").GetString()!, AuthServerFixture.AudienceOf("crm.read"));
        Assert.Equal(2, jwt.Audiences.Count());
    }

    [Fact]
    public async Task ClientCredentials_secret_post_is_accepted_only_when_registered()
    {
        using var c = NewClient();
        var (client, secret) = await c.ConfidentialClientAsync(method: ClientAuthMethods.SecretPost);
        var ok = await c.PostFormAsync("/oauth2/token", OAuthTestClient.Form(("grant_type", "client_credentials"), ("client_id", client.ClientId), ("client_secret", secret)));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        var basic = await c.ClientCredentialsAsync(client.ClientId, secret);
        Assert.Equal(HttpStatusCode.Unauthorized, basic.StatusCode);
    }

    [Fact]
    public async Task ClientCredentials_wrong_secret_is_invalid_client_with_challenge()
    {
        using var c = NewClient();
        var (client, _) = await c.ConfidentialClientAsync();
        var response = await c.ClientCredentialsAsync(client.ClientId, "aasec_wrong");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Basic", response.Headers.WwwAuthenticate.ToString());
        Assert.Equal("invalid_client", (await OAuthTestClient.JsonAsync(response)).GetProperty("error").GetString());

        var unknown = await c.ClientCredentialsAsync("does-not-exist", "x");
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
    }

    [Fact]
    public async Task ClientCredentials_rejects_scope_not_allowed_or_identity_scope()
    {
        using var c = NewClient();
        var (client, secret) = await c.ConfidentialClientAsync(scopes: ["erp.read"]);
        foreach (var scope in new[] { "erp.write", "openid", "erp.read nope" })
        {
            var response = await c.ClientCredentialsAsync(client.ClientId, secret, scope);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("invalid_scope", (await OAuthTestClient.JsonAsync(response)).GetProperty("error").GetString());
        }
    }

    [Fact]
    public async Task Token_endpoint_rejects_multiple_auth_methods_duplicates_and_json()
    {
        using var c = NewClient();
        var (client, secret) = await c.ConfidentialClientAsync();

        var both = await c.PostFormAsync("/oauth2/token",
            OAuthTestClient.Form(("grant_type", "client_credentials"), ("client_secret", secret), ("client_id", client.ClientId)), (client.ClientId, secret));
        Assert.Equal("invalid_request", (await OAuthTestClient.JsonAsync(both)).GetProperty("error").GetString());

        var duplicate = await c.PostFormAsync("/oauth2/token",
            [new("grant_type", "client_credentials"), new("grant_type", "client_credentials")], (client.ClientId, secret));
        Assert.Equal("invalid_request", (await OAuthTestClient.JsonAsync(duplicate)).GetProperty("error").GetString());

        using var json = new StringContent("{\"grant_type\":\"client_credentials\"}", Encoding.UTF8, "application/json");
        var jsonResponse = await c.Http.PostAsync("/oauth2/token", json);
        Assert.Equal(HttpStatusCode.BadRequest, jsonResponse.StatusCode);

        var unsupported = await c.PostFormAsync("/oauth2/token", OAuthTestClient.Form(("grant_type", "password"), ("username", "a"), ("password", "b")), (client.ClientId, secret));
        Assert.Equal("unsupported_grant_type", (await OAuthTestClient.JsonAsync(unsupported)).GetProperty("error").GetString());
    }

    [Fact]
    public async Task Public_client_cannot_use_client_credentials()
    {
        using var c = NewClient();
        var spa = await c.PublicClientAsync();
        var response = await c.PostFormAsync("/oauth2/token", OAuthTestClient.Form(("grant_type", "client_credentials"), ("client_id", spa.ClientId)));
        Assert.Equal("unauthorized_client", (await OAuthTestClient.JsonAsync(response)).GetProperty("error").GetString());
    }

    // ------------------------------------------------------------------ private_key_jwt

    [Fact]
    public async Task PrivateKeyJwt_valid_assertion_issues_token_and_replay_is_rejected()
    {
        using var c = NewClient();
        var (client, key) = await c.PrivateKeyJwtClientAsync();
        var assertion = c.ClientAssertion(client.ClientId, key);
        List<KeyValuePair<string, string>> Form() => OAuthTestClient.Form(("grant_type", "client_credentials"),
            ("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"), ("client_assertion", assertion));

        var first = await c.PostFormAsync("/oauth2/token", Form());
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        var replay = await c.PostFormAsync("/oauth2/token", Form());
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task PrivateKeyJwt_rejects_wrong_audience_long_lifetime_and_foreign_key()
    {
        using var c = NewClient();
        var (client, key) = await c.PrivateKeyJwtClientAsync();
        using var other = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);

        foreach (var assertion in new[]
        {
            c.ClientAssertion(client.ClientId, key, audience: "https://evil.example/token"),
            c.ClientAssertion(client.ClientId, key, lifetime: TimeSpan.FromHours(2)),
            c.ClientAssertion(client.ClientId, other),
        })
        {
            var response = await c.PostFormAsync("/oauth2/token", OAuthTestClient.Form(("grant_type", "client_credentials"),
                ("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"), ("client_assertion", assertion)));
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
    }

    // ------------------------------------------------------------------ authorization code + PKCE

    [Fact]
    public async Task AuthorizationCode_full_flow_with_id_token_userinfo_and_refresh_rotation()
    {
        using var c = NewClient();
        var spa = await c.PublicClientAsync();
        var user = await c.UserAsync();
        var verifier = OAuthTestClient.NewVerifier();

        var page = await c.GetLoginPageAsync(c.AuthorizeUrl(spa.ClientId, verifier));
        Assert.Equal(HttpStatusCode.OK, page.Response.StatusCode);
        Assert.NotNull(page.Cookie);
        var csp = page.Response.Headers.GetValues("Content-Security-Policy").Single();
        Assert.Contains("frame-ancestors 'none'", csp);
        Assert.Contains("form-action 'self' https://app.addaccion.test", csp);
        Assert.Contains(page.Hidden, h => h.Key == "csrf_token");

        var login = await c.SubmitLoginAsync(page, user.LoginName, user.Password);
        Assert.Equal(HttpStatusCode.SeeOther, login.StatusCode);
        var location = login.Headers.Location!;
        Assert.StartsWith(OAuthTestClient.RedirectUri, location.ToString());
        var query = OAuthTestClient.QueryOf(location);
        Assert.Equal("st-123", query["state"]);
        Assert.Equal(Fixture.Issuer, query["iss"]);

        var tokenResponse = await c.ExchangeCodeAsync(spa.ClientId, query["code"], verifier);
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);
        var tokens = await OAuthTestClient.JsonAsync(tokenResponse);
        var accessToken = tokens.GetProperty("access_token").GetString()!;
        var refreshToken = tokens.GetProperty("refresh_token").GetString()!;

        var at = await c.ValidateWithJwksAsync(accessToken, AuthServerFixture.AudienceOf("erp.read"));
        Assert.Equal(user.UserId, at.Subject);
        Assert.Equal(spa.ClientId, at.GetPayloadValue<string>("client_id"));
        Assert.Contains("rrhh", at.GetPayloadValue<string[]>("roles"));
        Assert.True(at.TryGetPayloadValue<long>("auth_time", out _));
        Assert.False(at.TryGetPayloadValue<string>("email", out _)); // no profile PII in access tokens

        var idToken = await c.ValidateWithJwksAsync(tokens.GetProperty("id_token").GetString()!, spa.ClientId, type: "JWT");
        Assert.Equal("n-456", idToken.GetPayloadValue<string>("nonce"));
        Assert.Equal(user.Email, idToken.GetPayloadValue<string>("email"));
        Assert.Equal(AddAccion.Auth.Protocol.TokenService.AtHash(accessToken, idToken.Alg), idToken.GetPayloadValue<string>("at_hash"));

        using var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "/oauth2/userinfo");
        userInfoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var userInfo = await OAuthTestClient.JsonAsync(await c.Http.SendAsync(userInfoRequest));
        Assert.Equal(user.UserId, userInfo.GetProperty("sub").GetString());
        Assert.Equal(user.LoginName, userInfo.GetProperty("preferred_username").GetString());
        Assert.Equal("Ana", userInfo.GetProperty("given_name").GetString());

        // Refresh with down-scoping, then reuse detection revokes the whole family.
        var refreshed = await c.RefreshAsync(spa.ClientId, refreshToken, scope: "openid erp.read");
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        var second = await OAuthTestClient.JsonAsync(refreshed);
        Assert.Equal("openid erp.read", second.GetProperty("scope").GetString());
        var rotated = second.GetProperty("refresh_token").GetString()!;
        Assert.NotEqual(refreshToken, rotated);

        var reuse = await c.RefreshAsync(spa.ClientId, refreshToken);
        Assert.Equal("invalid_grant", (await OAuthTestClient.JsonAsync(reuse)).GetProperty("error").GetString());
        var afterReuse = await c.RefreshAsync(spa.ClientId, rotated);
        Assert.Equal("invalid_grant", (await OAuthTestClient.JsonAsync(afterReuse)).GetProperty("error").GetString());
    }

    [Fact]
    public async Task Refresh_cannot_widen_scope_or_be_used_by_another_client()
    {
        using var c = NewClient();
        var spa = await c.PublicClientAsync();
        var other = await c.PublicClientAsync();
        var user = await c.UserAsync();
        var verifier = OAuthTestClient.NewVerifier();
        var code = await c.LoginForCodeAsync(spa, user, verifier, scope: "openid erp.read");
        var tokens = await OAuthTestClient.JsonAsync(await c.ExchangeCodeAsync(spa.ClientId, code, verifier));
        var refresh = tokens.GetProperty("refresh_token").GetString()!;

        var widened = await c.RefreshAsync(spa.ClientId, refresh, scope: "openid erp.read erp.write");
        Assert.Equal("invalid_scope", (await OAuthTestClient.JsonAsync(widened)).GetProperty("error").GetString());

        var stolen = await c.RefreshAsync(other.ClientId, refresh);
        Assert.Equal("invalid_grant", (await OAuthTestClient.JsonAsync(stolen)).GetProperty("error").GetString());
        // Presentation by another client is treated as theft: the family is revoked for the owner too.
        var owner = await c.RefreshAsync(spa.ClientId, refresh);
        Assert.Equal("invalid_grant", (await OAuthTestClient.JsonAsync(owner)).GetProperty("error").GetString());
    }

    [Fact]
    public async Task Authorize_with_unregistered_redirect_uri_or_unknown_client_never_redirects()
    {
        using var c = NewClient();
        var spa = await c.PublicClientAsync();
        var verifier = OAuthTestClient.NewVerifier();

        var badRedirect = await c.Http.GetAsync(c.AuthorizeUrl(spa.ClientId, verifier, redirectUri: "https://evil.example/cb"));
        Assert.Equal(HttpStatusCode.BadRequest, badRedirect.StatusCode);
        Assert.Null(badRedirect.Headers.Location);

        var prefixAttack = await c.Http.GetAsync(c.AuthorizeUrl(spa.ClientId, verifier, redirectUri: OAuthTestClient.RedirectUri + ".evil.example"));
        Assert.Null(prefixAttack.Headers.Location);

        var unknown = await c.Http.GetAsync(c.AuthorizeUrl("nope-" + Guid.NewGuid(), verifier));
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        Assert.Null(unknown.Headers.Location);
    }

    [Fact]
    public async Task Authorize_requires_pkce_s256_and_valid_scope()
    {
        using var c = NewClient();
        var spa = await c.PublicClientAsync();
        var verifier = OAuthTestClient.NewVerifier();

        async Task AssertRedirectError(string url, string error)
        {
            var response = await c.Http.GetAsync(url);
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            var q = OAuthTestClient.QueryOf(response.Headers.Location!);
            Assert.Equal(error, q["error"]);
            Assert.Equal("st-123", q["state"]);
            Assert.Equal(Fixture.Issuer, q["iss"]);
        }

        await AssertRedirectError(c.AuthorizeUrl(spa.ClientId, verifier, includeChallenge: false), "invalid_request");
        await AssertRedirectError(c.AuthorizeUrl(spa.ClientId, verifier, method: "plain"), "invalid_request");
        await AssertRedirectError(c.AuthorizeUrl(spa.ClientId, verifier, method: null), "invalid_request");
        await AssertRedirectError(c.AuthorizeUrl(spa.ClientId, verifier, scope: "openid crm.read"), "invalid_scope");
        await AssertRedirectError(c.AuthorizeUrl(spa.ClientId, verifier) + "&prompt=none", "login_required");
        await AssertRedirectError(c.AuthorizeUrl(spa.ClientId, verifier).Replace("response_type=code", "response_type=token", StringComparison.Ordinal),
            "unsupported_response_type");
    }

    [Fact]
    public async Task Loopback_redirect_uri_accepts_any_port_for_native_apps()
    {
        using var c = NewClient();
        var spa = await c.PublicClientAsync();
        var page = await c.GetLoginPageAsync(c.AuthorizeUrl(spa.ClientId, OAuthTestClient.NewVerifier(), redirectUri: "http://127.0.0.1:53123/native-callback"));
        Assert.Equal(HttpStatusCode.OK, page.Response.StatusCode);
    }

    [Fact]
    public async Task Code_exchange_validates_verifier_redirect_and_client()
    {
        using var c = NewClient();
        var spa = await c.PublicClientAsync();
        var other = await c.PublicClientAsync();
        var user = await c.UserAsync();
        var verifier = OAuthTestClient.NewVerifier();
        var code = await c.LoginForCodeAsync(spa, user, verifier);

        var wrongVerifier = await c.ExchangeCodeAsync(spa.ClientId, code, OAuthTestClient.NewVerifier());
        Assert.Equal("invalid_grant", (await OAuthTestClient.JsonAsync(wrongVerifier)).GetProperty("error").GetString());
        var wrongRedirect = await c.ExchangeCodeAsync(spa.ClientId, code, verifier, "http://127.0.0.1/native-callback");
        Assert.Equal("invalid_grant", (await OAuthTestClient.JsonAsync(wrongRedirect)).GetProperty("error").GetString());
        var wrongClient = await c.ExchangeCodeAsync(other.ClientId, code, verifier);
        Assert.Equal("invalid_grant", (await OAuthTestClient.JsonAsync(wrongClient)).GetProperty("error").GetString());

        // Failed attempts do not burn the code for its legitimate holder (verifier has 256 bits of entropy).
        var ok = await c.ExchangeCodeAsync(spa.ClientId, code, verifier);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
    }

    [Fact]
    public async Task Code_replay_revokes_tokens_issued_from_it()
    {
        using var c = NewClient();
        var spa = await c.PublicClientAsync();
        var (introspector, secret) = await c.ConfidentialClientAsync(canIntrospect: true);
        var user = await c.UserAsync();
        var verifier = OAuthTestClient.NewVerifier();
        var code = await c.LoginForCodeAsync(spa, user, verifier);

        var tokens = await OAuthTestClient.JsonAsync(await c.ExchangeCodeAsync(spa.ClientId, code, verifier));
        var replay = await c.ExchangeCodeAsync(spa.ClientId, code, verifier);
        Assert.Equal("invalid_grant", (await OAuthTestClient.JsonAsync(replay)).GetProperty("error").GetString());

        var refresh = await c.RefreshAsync(spa.ClientId, tokens.GetProperty("refresh_token").GetString()!);
        Assert.Equal("invalid_grant", (await OAuthTestClient.JsonAsync(refresh)).GetProperty("error").GetString());

        var introspection = await OAuthTestClient.JsonAsync(await c.PostFormAsync("/oauth2/introspect",
            OAuthTestClient.Form(("token", tokens.GetProperty("access_token").GetString())), (introspector.ClientId, secret)));
        Assert.False(introspection.GetProperty("active").GetBoolean());
    }

    // ------------------------------------------------------------------ login security

    [Fact]
    public async Task Login_failures_are_generic_and_lock_the_account()
    {
        using var c = NewClient();
        var spa = await c.PublicClientAsync();
        var user = await c.UserAsync();
        var url = c.AuthorizeUrl(spa.ClientId, OAuthTestClient.NewVerifier());

        var unknownPage = await c.GetLoginPageAsync(url);
        var unknown = await c.SubmitLoginAsync(unknownPage, "nobody-" + Guid.NewGuid(), "whatever-123");
        var unknownHtml = await unknown.Content.ReadAsStringAsync();

        for (var i = 0; i < AuthServerFixture.MaxFailedAttempts; i++)
        {
            var page = await c.GetLoginPageAsync(url);
            var failed = await c.SubmitLoginAsync(page, user.LoginName, "wrong-password");
            Assert.Equal(HttpStatusCode.BadRequest, failed.StatusCode);
            Assert.Null(failed.Headers.Location);
            var html = await failed.Content.ReadAsStringAsync();
            Assert.Contains("Usuario o contraseña incorrectos.", html);
        }
        Assert.Contains("Usuario o contraseña incorrectos.", unknownHtml);

        // Locked: even the right password is refused, with the same message.
        var lockedPage = await c.GetLoginPageAsync(url);
        var locked = await c.SubmitLoginAsync(lockedPage, user.LoginName, user.Password);
        Assert.Equal(HttpStatusCode.BadRequest, locked.StatusCode);
        Assert.Contains("Usuario o contraseña incorrectos.", await locked.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Login_post_requires_csrf_cookie_and_same_origin()
    {
        using var c = NewClient();
        var spa = await c.PublicClientAsync();
        var user = await c.UserAsync();
        var page = await c.GetLoginPageAsync(c.AuthorizeUrl(spa.ClientId, OAuthTestClient.NewVerifier()));

        var noCookie = await c.SubmitLoginAsync(page, user.LoginName, user.Password, sendCookie: false);
        Assert.Equal(HttpStatusCode.BadRequest, noCookie.StatusCode);
        Assert.Null(noCookie.Headers.Location);

        var crossOrigin = await c.SubmitLoginAsync(page, user.LoginName, user.Password, origin: "https://evil.example");
        Assert.Equal(HttpStatusCode.Forbidden, crossOrigin.StatusCode);

        var tampered = page with { Hidden = page.Hidden.Select(h => h.Key == "csrf_token" ? new KeyValuePair<string, string>(h.Key, "x" + h.Value[1..]) : h).ToList() };
        var forged = await c.SubmitLoginAsync(tampered, user.LoginName, user.Password);
        Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);

        var tamperedRedirect = page with { Hidden = page.Hidden.Select(h => h.Key == "redirect_uri" ? new KeyValuePair<string, string>(h.Key, "https://evil.example/cb") : h).ToList() };
        var redirected = await c.SubmitLoginAsync(tamperedRedirect, user.LoginName, user.Password);
        Assert.Null(redirected.Headers.Location);
    }

    [Fact]
    public async Task Inactive_user_cannot_log_in_or_redeem_or_refresh()
    {
        using var c = NewClient();
        var spa = await c.PublicClientAsync();
        var user = await c.UserAsync();
        var verifier = OAuthTestClient.NewVerifier();
        var code = await c.LoginForCodeAsync(spa, user, verifier);
        var tokens = await OAuthTestClient.JsonAsync(await c.ExchangeCodeAsync(spa.ClientId, code, verifier));

        await Fixture.SetUserActiveAsync(user.UserId, false);

        var refresh = await c.RefreshAsync(spa.ClientId, tokens.GetProperty("refresh_token").GetString()!);
        Assert.Equal("invalid_grant", (await OAuthTestClient.JsonAsync(refresh)).GetProperty("error").GetString());

        var page = await c.GetLoginPageAsync(c.AuthorizeUrl(spa.ClientId, verifier));
        var login = await c.SubmitLoginAsync(page, user.LoginName, user.Password);
        Assert.Equal(HttpStatusCode.BadRequest, login.StatusCode);
    }

    // ------------------------------------------------------------------ introspection / revocation

    [Fact]
    public async Task Introspection_requires_permission_and_reports_active_tokens()
    {
        using var c = NewClient();
        var (api, apiSecret) = await c.ConfidentialClientAsync(canIntrospect: true);
        var (caller, callerSecret) = await c.ConfidentialClientAsync();
        var token = (await OAuthTestClient.JsonAsync(await c.ClientCredentialsAsync(caller.ClientId, callerSecret))).GetProperty("access_token").GetString()!;

        var forbidden = await c.PostFormAsync("/oauth2/introspect", OAuthTestClient.Form(("token", token)), (caller.ClientId, callerSecret));
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        var unauthenticated = await c.PostFormAsync("/oauth2/introspect", OAuthTestClient.Form(("token", token)));
        Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);

        var active = await OAuthTestClient.JsonAsync(await c.PostFormAsync("/oauth2/introspect", OAuthTestClient.Form(("token", token)), (api.ClientId, apiSecret)));
        Assert.True(active.GetProperty("active").GetBoolean());
        Assert.Equal(caller.ClientId, active.GetProperty("client_id").GetString());
        Assert.Equal("erp.read", active.GetProperty("scope").GetString());

        var tampered = token[..^4] + (token[^4] == 'A' ? "BBBB" : "AAAA");
        var inactive = await OAuthTestClient.JsonAsync(await c.PostFormAsync("/oauth2/introspect", OAuthTestClient.Form(("token", tampered)), (api.ClientId, apiSecret)));
        Assert.False(inactive.GetProperty("active").GetBoolean());
        Assert.Single(inactive.EnumerateObject());
    }

    [Fact]
    public async Task Forged_tokens_alg_none_and_hmac_key_confusion_are_inactive()
    {
        using var c = NewClient();
        var (api, apiSecret) = await c.ConfidentialClientAsync(canIntrospect: true);
        var (client, secret) = await c.ConfidentialClientAsync();
        var real = (await OAuthTestClient.JsonAsync(await c.ClientCredentialsAsync(client.ClientId, secret))).GetProperty("access_token").GetString()!;
        var parts = real.Split('.');
        var header = JsonSerializer.Deserialize<Dictionary<string, string>>(Base64UrlEncoder.Decode(parts[0]))!;

        string Header(string alg) => Base64UrlEncoder.Encode($$"""{"alg":"{{alg}}","kid":"{{header["kid"]}}","typ":"at+jwt"}""");
        var none = Header("none") + "." + parts[1] + ".";
        // HS256 "signed" with the public JWKS material: classic RS256 -> HS256 confusion attack.
        var jwks = await c.Http.GetStringAsync("/.well-known/jwks.json");
        var signingInput = Header("HS256") + "." + parts[1];
        var mac = System.Security.Cryptography.HMACSHA256.HashData(Encoding.UTF8.GetBytes(jwks), Encoding.ASCII.GetBytes(signingInput));
        var hmac = signingInput + "." + Base64UrlEncoder.Encode(mac);

        foreach (var forged in new[] { none, hmac })
        {
            var result = await OAuthTestClient.JsonAsync(await c.PostFormAsync("/oauth2/introspect", OAuthTestClient.Form(("token", forged)), (api.ClientId, apiSecret)));
            Assert.False(result.GetProperty("active").GetBoolean());
        }
    }

    [Fact]
    public async Task Revocation_of_access_and_refresh_tokens()
    {
        using var c = NewClient();
        var (api, apiSecret) = await c.ConfidentialClientAsync(canIntrospect: true);
        var (client, secret) = await c.ConfidentialClientAsync();
        var token = (await OAuthTestClient.JsonAsync(await c.ClientCredentialsAsync(client.ClientId, secret))).GetProperty("access_token").GetString()!;

        // Another client cannot revoke it (silently ignored, still 200).
        var foreign = await c.PostFormAsync("/oauth2/revoke", OAuthTestClient.Form(("token", token)), (api.ClientId, apiSecret));
        Assert.Equal(HttpStatusCode.OK, foreign.StatusCode);
        var stillActive = await OAuthTestClient.JsonAsync(await c.PostFormAsync("/oauth2/introspect", OAuthTestClient.Form(("token", token)), (api.ClientId, apiSecret)));
        Assert.True(stillActive.GetProperty("active").GetBoolean());

        var revoke = await c.PostFormAsync("/oauth2/revoke", OAuthTestClient.Form(("token", token), ("token_type_hint", "access_token")), (client.ClientId, secret));
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        var revoked = await OAuthTestClient.JsonAsync(await c.PostFormAsync("/oauth2/introspect", OAuthTestClient.Form(("token", token)), (api.ClientId, apiSecret)));
        Assert.False(revoked.GetProperty("active").GetBoolean());

        var garbage = await c.PostFormAsync("/oauth2/revoke", OAuthTestClient.Form(("token", "not-a-token")), (client.ClientId, secret));
        Assert.Equal(HttpStatusCode.OK, garbage.StatusCode);

        // Public client revokes its refresh token (logout).
        var spa = await c.PublicClientAsync();
        var user = await c.UserAsync();
        var verifier = OAuthTestClient.NewVerifier();
        var code = await c.LoginForCodeAsync(spa, user, verifier);
        var refresh = (await OAuthTestClient.JsonAsync(await c.ExchangeCodeAsync(spa.ClientId, code, verifier))).GetProperty("refresh_token").GetString()!;
        var logout = await c.PostFormAsync("/oauth2/revoke", OAuthTestClient.Form(("token", refresh), ("client_id", spa.ClientId)));
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
        var afterLogout = await c.RefreshAsync(spa.ClientId, refresh);
        Assert.Equal("invalid_grant", (await OAuthTestClient.JsonAsync(afterLogout)).GetProperty("error").GetString());
    }

    [Fact]
    public async Task UserInfo_rejects_missing_invalid_and_machine_tokens()
    {
        using var c = NewClient();
        var none = await c.Http.GetAsync("/oauth2/userinfo");
        Assert.Equal(HttpStatusCode.Unauthorized, none.StatusCode);

        var (client, secret) = await c.ConfidentialClientAsync();
        var machine = (await OAuthTestClient.JsonAsync(await c.ClientCredentialsAsync(client.ClientId, secret))).GetProperty("access_token").GetString()!;
        using var request = new HttpRequestMessage(HttpMethod.Get, "/oauth2/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", machine);
        var response = await c.Http.SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("insufficient_scope", response.Headers.WwwAuthenticate.ToString());
    }

    // ------------------------------------------------------------------ admin API

    [Fact]
    public async Task Admin_api_creates_clients_and_rotates_secrets()
    {
        using var c = NewClient();
        var (admin, adminSecret) = await c.ConfidentialClientAsync(scopes: ["auth.admin"]);
        var adminToken = (await OAuthTestClient.JsonAsync(await c.ClientCredentialsAsync(admin.ClientId, adminSecret, "auth.admin"))).GetProperty("access_token").GetString()!;
        var (plain, plainSecret) = await c.ConfidentialClientAsync();
        var plainToken = (await OAuthTestClient.JsonAsync(await c.ClientCredentialsAsync(plain.ClientId, plainSecret))).GetProperty("access_token").GetString()!;

        var newId = OAuthTestClient.Unique("partner");
        var body = $$"""{"client_id":"{{newId}}","client_name":"Partner","client_type":"confidential","grant_types":["client_credentials"],"scopes":["erp.read"]}""";

        HttpRequestMessage Create(string? bearer)
        {
            var r = new HttpRequestMessage(HttpMethod.Post, "/admin/v1/clients") { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            if (bearer is not null) r.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            return r;
        }

        using (var r = Create(null)) Assert.Equal(HttpStatusCode.Unauthorized, (await c.Http.SendAsync(r)).StatusCode);
        using (var r = Create(plainToken)) Assert.Equal(HttpStatusCode.Forbidden, (await c.Http.SendAsync(r)).StatusCode);

        JsonElement created;
        using (var r = Create(adminToken))
        {
            var response = await c.Http.SendAsync(r);
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            created = await OAuthTestClient.JsonAsync(response);
        }
        var newSecret = created.GetProperty("client_secret").GetString()!;
        Assert.StartsWith("aasec_", newSecret);
        Assert.Equal(HttpStatusCode.OK, (await c.ClientCredentialsAsync(newId, newSecret)).StatusCode);

        using (var r = Create(adminToken)) Assert.Equal(HttpStatusCode.Conflict, (await c.Http.SendAsync(r)).StatusCode);

        using var rotate = new HttpRequestMessage(HttpMethod.Post, $"/admin/v1/clients/{newId}/secrets")
        {
            Content = new StringContent("{\"description\":\"rotation\",\"lifetime_days\":30}", Encoding.UTF8, "application/json"),
        };
        rotate.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        var rotated = await OAuthTestClient.JsonAsync(await c.Http.SendAsync(rotate));
        var second = rotated.GetProperty("client_secret").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await c.ClientCredentialsAsync(newId, second)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await c.ClientCredentialsAsync(newId, newSecret)).StatusCode);

        using var disable = new HttpRequestMessage(HttpMethod.Post, $"/admin/v1/clients/{newId}/disable");
        disable.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        Assert.Equal(HttpStatusCode.NoContent, (await c.Http.SendAsync(disable)).StatusCode);
    }

    [Fact]
    public async Task Admin_api_rejects_insecure_client_metadata()
    {
        using var c = NewClient();
        var (admin, adminSecret) = await c.ConfidentialClientAsync(scopes: ["auth.admin"]);
        var token = (await OAuthTestClient.JsonAsync(await c.ClientCredentialsAsync(admin.ClientId, adminSecret))).GetProperty("access_token").GetString()!;

        string[] invalid =
        [
            """{"client_id":"x1-bad","client_name":"n","client_type":"public","grant_types":["authorization_code"],"redirect_uris":["https://*.addaccion.com/cb"],"scopes":["openid"]}""",
            """{"client_id":"x2-bad","client_name":"n","client_type":"public","grant_types":["authorization_code"],"redirect_uris":["http://app.addaccion.com/cb"],"scopes":["openid"]}""",
            """{"client_id":"x3-bad","client_name":"n","client_type":"public","grant_types":["client_credentials"],"scopes":["erp.read"]}""",
            """{"client_id":"x4-bad","client_name":"n","client_type":"confidential","token_endpoint_auth_method":"private_key_jwt","grant_types":["client_credentials"],"scopes":["erp.read"],"jwks":{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}}""",
            """{"client_id":"x5-bad","client_name":"n","client_type":"confidential","grant_types":["password"],"scopes":["erp.read"]}""",
        ];
        foreach (var body in invalid)
        {
            using var r = new HttpRequestMessage(HttpMethod.Post, "/admin/v1/clients") { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            r.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var response = await c.Http.SendAsync(r);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    // ------------------------------------------------------------------ hardening

    [Fact]
    public async Task Responses_carry_security_headers()
    {
        using var c = NewClient();
        var response = await c.Http.GetAsync("/.well-known/jwks.json");
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.False(response.Headers.Contains("Server"));

        var notFound = await c.Http.GetAsync("/does-not-exist");
        Assert.Equal(HttpStatusCode.NotFound, notFound.StatusCode);
    }
}

public sealed class InMemoryProtocolTests(InMemoryFixture fixture) : ProtocolTests<InMemoryFixture>(fixture);

public sealed class SqlServerProtocolTests(SqlServerFixture fixture) : ProtocolTests<SqlServerFixture>(fixture);

public sealed class ExternalProtocolTests(ExternalFixture fixture) : ProtocolTests<ExternalFixture>(fixture);
