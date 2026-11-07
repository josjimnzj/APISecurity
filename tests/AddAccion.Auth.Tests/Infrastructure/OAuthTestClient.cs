using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AddAccion.Auth.Crypto;
using AddAccion.Auth.Domain;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AddAccion.Auth.Tests.Infrastructure;

/// <summary>HTTP-only helper: everything a third-party OAuth client would do, nothing more.</summary>
public sealed partial class OAuthTestClient(AuthServerFixture fixture) : IDisposable
{
    public HttpClient Http { get; } = fixture.CreateClient();
    public AuthServerFixture Fixture => fixture;

    public static string Unique(string prefix) => prefix + "-" + Guid.NewGuid().ToString("N")[..10];

    // ---- seeding -------------------------------------------------------------
    public async Task<(ClientApplication Client, string Secret)> ConfidentialClientAsync(
        string[]? scopes = null, string[]? grants = null, string method = ClientAuthMethods.SecretBasic, bool canIntrospect = false,
        string[]? redirectUris = null, int accessTokenLifetime = 600, int refreshTokenLifetime = 3600)
    {
        var secret = RandomTokens.CreateClientSecret();
        var client = new ClientApplication
        {
            ClientId = Unique("conf"),
            ClientName = "Sistema externo de prueba",
            ClientType = ClientType.Confidential,
            TokenEndpointAuthMethod = method,
            AllowedGrantTypes = grants ?? [GrantTypes.ClientCredentials],
            RedirectUris = redirectUris ?? [],
            AllowedScopes = scopes ?? ["erp.read"],
            Secrets = [new ClientSecretInfo(0, TokenHasher.Hash(secret), "test", DateTimeOffset.UtcNow, null)],
            CanIntrospect = canIntrospect,
            AccessTokenLifetimeSeconds = accessTokenLifetime,
            RefreshTokenLifetimeSeconds = refreshTokenLifetime,
        };
        await fixture.SeedClientAsync(client);
        return (client, secret);
    }

    public async Task<(ClientApplication Client, ECDsa Key)> PrivateKeyJwtClientAsync(string[]? scopes = null)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(ECDsa.Create(key.ExportParameters(false))));
        var jwks = $$"""{"keys":[{"kty":"EC","crv":"P-256","x":"{{jwk.X}}","y":"{{jwk.Y}}","kid":"k1","use":"sig"}]}""";
        var client = new ClientApplication
        {
            ClientId = Unique("pkjwt"),
            ClientName = "Sistema con clave privada",
            ClientType = ClientType.Confidential,
            TokenEndpointAuthMethod = ClientAuthMethods.PrivateKeyJwt,
            AllowedGrantTypes = [GrantTypes.ClientCredentials],
            RedirectUris = [],
            AllowedScopes = scopes ?? ["erp.read"],
            Jwks = jwks,
        };
        await fixture.SeedClientAsync(client);
        return (client, key);
    }

    public const string RedirectUri = "https://app.addaccion.test/callback";

    public async Task<ClientApplication> PublicClientAsync(string[]? scopes = null, int refreshTokenLifetime = 3600)
    {
        var client = new ClientApplication
        {
            ClientId = Unique("spa"),
            ClientName = "Portal AddACCION",
            ClientType = ClientType.Public,
            TokenEndpointAuthMethod = ClientAuthMethods.None,
            AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken],
            RedirectUris = [RedirectUri, "http://127.0.0.1/native-callback"],
            AllowedScopes = scopes ?? ["openid", "profile", "email", "roles", "offline_access", "erp.read", "erp.write"],
            RefreshTokenLifetimeSeconds = refreshTokenLifetime,
        };
        await fixture.SeedClientAsync(client);
        return client;
    }

    public async Task<UserSeed> UserAsync(string password = "Correct-Horse-9", string[]? roles = null)
    {
        var id = Guid.NewGuid().ToString().ToUpperInvariant();
        var login = Unique("user");
        var user = new UserSeed(id, login, password, login + "@addaccion.test", roles ?? ["empleado", "rrhh"]);
        await fixture.SeedUserAsync(user);
        return user;
    }

    // ---- token endpoint -------------------------------------------------------
    public async Task<HttpResponseMessage> PostFormAsync(string path, IEnumerable<KeyValuePair<string, string>> form, (string Id, string Secret)? basic = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = new FormUrlEncodedContent(form) };
        if (basic is { } b)
        {
            var raw = Uri.EscapeDataString(b.Id) + ":" + Uri.EscapeDataString(b.Secret);
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(raw)));
        }
        return await Http.SendAsync(request);
    }

    public static async Task<JsonElement> JsonAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        return doc.RootElement.Clone();
    }

    public Task<HttpResponseMessage> ClientCredentialsAsync(string clientId, string secret, string? scope = null) =>
        PostFormAsync("/oauth2/token", Form(("grant_type", "client_credentials"), ("scope", scope)), (clientId, secret));

    public static List<KeyValuePair<string, string>> Form(params (string Key, string? Value)[] values) =>
        values.Where(v => v.Value is not null).Select(v => new KeyValuePair<string, string>(v.Key, v.Value!)).ToList();

    public string ClientAssertion(string clientId, ECDsa key, string? audience = null, string? jti = null, TimeSpan? lifetime = null, DateTime? now = null)
    {
        var issuedAt = now ?? (fixture.Clock?.GetUtcNow().UtcDateTime ?? DateTime.UtcNow);
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = audience ?? fixture.Issuer + "/oauth2/token",
            IssuedAt = issuedAt,
            NotBefore = issuedAt,
            Expires = issuedAt + (lifetime ?? TimeSpan.FromMinutes(2)),
            Claims = new Dictionary<string, object> { ["sub"] = clientId, ["jti"] = jti ?? Guid.NewGuid().ToString("N") },
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key) { KeyId = "k1" }, SecurityAlgorithms.EcdsaSha256),
        };
        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(descriptor);
    }

    // ---- authorization code flow (browser simulation) -----------------------------
    public sealed record LoginPage(HttpResponseMessage Response, string Html, string? Cookie, List<KeyValuePair<string, string>> Hidden);

    public static string NewVerifier() => RandomTokens.Create(32);

    public string AuthorizeUrl(string clientId, string verifier, string scope = "openid profile email roles erp.read", string? state = "st-123",
        string? nonce = "n-456", string redirectUri = RedirectUri, string? method = "S256", bool includeChallenge = true)
    {
        var q = new List<string>
        {
            "response_type=code",
            "client_id=" + Uri.EscapeDataString(clientId),
            "redirect_uri=" + Uri.EscapeDataString(redirectUri),
            "scope=" + Uri.EscapeDataString(scope),
        };
        if (state is not null) q.Add("state=" + Uri.EscapeDataString(state));
        if (nonce is not null) q.Add("nonce=" + Uri.EscapeDataString(nonce));
        if (includeChallenge) q.Add("code_challenge=" + Pkce.S256(verifier));
        if (method is not null) q.Add("code_challenge_method=" + method);
        return "/oauth2/authorize?" + string.Join('&', q);
    }

    public async Task<LoginPage> GetLoginPageAsync(string url)
    {
        var response = await Http.GetAsync(url);
        var html = await response.Content.ReadAsStringAsync();
        string? cookie = null;
        if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
            cookie = cookies.Select(c => c.Split(';')[0]).FirstOrDefault(c => c.Contains("aa_csrf", StringComparison.Ordinal));
        var hidden = HiddenInput().Matches(html)
            .Select(m => new KeyValuePair<string, string>(WebUtility.HtmlDecode(m.Groups[1].Value), WebUtility.HtmlDecode(m.Groups[2].Value)))
            .ToList();
        return new LoginPage(response, html, cookie, hidden);
    }

    [GeneratedRegex("<input type=\"hidden\" name=\"([^\"]*)\" value=\"([^\"]*)\">")]
    private static partial Regex HiddenInput();

    public async Task<HttpResponseMessage> SubmitLoginAsync(LoginPage page, string username, string password, string? origin = null, bool sendCookie = true)
    {
        var form = new List<KeyValuePair<string, string>>(page.Hidden) { new("username", username), new("password", password) };
        using var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/authorize") { Content = new FormUrlEncodedContent(form) };
        if (sendCookie && page.Cookie is not null) request.Headers.Add("Cookie", page.Cookie);
        if (origin is not null) request.Headers.Add("Origin", origin);
        return await Http.SendAsync(request);
    }

    public static Dictionary<string, string> QueryOf(Uri location) =>
        location.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2))
            .ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p.Length > 1 ? p[1] : ""));

    /// <summary>Full browser leg: authorize -> login -> code.</summary>
    public async Task<string> LoginForCodeAsync(ClientApplication client, UserSeed user, string verifier, string scope = "openid profile email roles erp.read")
    {
        var page = await GetLoginPageAsync(AuthorizeUrl(client.ClientId, verifier, scope));
        Assert.Equal(HttpStatusCode.OK, page.Response.StatusCode);
        var response = await SubmitLoginAsync(page, user.LoginName, user.Password);
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        var query = QueryOf(response.Headers.Location!);
        return query["code"];
    }

    public Task<HttpResponseMessage> ExchangeCodeAsync(string clientId, string code, string verifier, string redirectUri = RedirectUri) =>
        PostFormAsync("/oauth2/token", Form(("grant_type", "authorization_code"), ("client_id", clientId), ("code", code),
            ("redirect_uri", redirectUri), ("code_verifier", verifier)));

    public Task<HttpResponseMessage> RefreshAsync(string clientId, string refreshToken, string? scope = null) =>
        PostFormAsync("/oauth2/token", Form(("grant_type", "refresh_token"), ("client_id", clientId), ("refresh_token", refreshToken), ("scope", scope)));

    // ---- validation like a resource server would do -------------------------------
    public async Task<JsonWebToken> ValidateWithJwksAsync(string token, string audience, string type = "at+jwt")
    {
        var jwks = new JsonWebKeySet(await Http.GetStringAsync("/.well-known/jwks.json"));
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = fixture.Issuer,
            ValidAudience = audience,
            IssuerSigningKeys = jwks.Keys,
            ValidTypes = [type],
            ValidateLifetime = fixture.Clock is null,
        });
        Assert.True(result.IsValid, result.Exception?.Message);
        return (JsonWebToken)result.SecurityToken;
    }

    public void Dispose() => Http.Dispose();
}
