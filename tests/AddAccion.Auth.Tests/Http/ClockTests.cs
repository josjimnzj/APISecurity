using System.Net;
using AddAccion.Auth.Crypto;
using AddAccion.Auth.Domain;
using AddAccion.Auth.Tests.Infrastructure;

namespace AddAccion.Auth.Tests.Http;

/// <summary>Expiry behaviour, driven by the server's injected clock (in-process fixtures only).</summary>
public abstract class ClockTests<TFixture>(TFixture fixture) : IClassFixture<TFixture>
    where TFixture : AuthServerFixture
{
    private OAuthTestClient NewClient()
    {
        fixture.SkipIfUnavailable();
        Assert.NotNull(fixture.Clock);
        return new OAuthTestClient(fixture);
    }

    [Fact]
    public async Task Authorization_code_expires_after_its_lifetime()
    {
        using var c = NewClient();
        var spa = await c.PublicClientAsync();
        var user = await c.UserAsync();
        var verifier = OAuthTestClient.NewVerifier();
        var code = await c.LoginForCodeAsync(spa, user, verifier);
        fixture.Clock!.Advance(TimeSpan.FromSeconds(61));
        var response = await c.ExchangeCodeAsync(spa.ClientId, code, verifier);
        Assert.Equal("invalid_grant", (await OAuthTestClient.JsonAsync(response)).GetProperty("error").GetString());
    }

    [Fact]
    public async Task Refresh_token_family_has_an_absolute_lifetime()
    {
        using var c = NewClient();
        var spa = await c.PublicClientAsync(refreshTokenLifetime: 3600);
        var user = await c.UserAsync();
        var verifier = OAuthTestClient.NewVerifier();
        var code = await c.LoginForCodeAsync(spa, user, verifier);
        var refresh = (await OAuthTestClient.JsonAsync(await c.ExchangeCodeAsync(spa.ClientId, code, verifier))).GetProperty("refresh_token").GetString()!;

        fixture.Clock!.Advance(TimeSpan.FromMinutes(30));
        var rotated = await OAuthTestClient.JsonAsync(await c.RefreshAsync(spa.ClientId, refresh));
        var next = rotated.GetProperty("refresh_token").GetString()!;

        // Rotation does not extend the family lifetime.
        fixture.Clock.Advance(TimeSpan.FromMinutes(31));
        var expired = await c.RefreshAsync(spa.ClientId, next);
        Assert.Equal("invalid_grant", (await OAuthTestClient.JsonAsync(expired)).GetProperty("error").GetString());
    }

    [Fact]
    public async Task Expired_access_token_is_inactive()
    {
        using var c = NewClient();
        var (api, apiSecret) = await c.ConfidentialClientAsync(canIntrospect: true);
        var (client, secret) = await c.ConfidentialClientAsync(accessTokenLifetime: 120);
        var token = (await OAuthTestClient.JsonAsync(await c.ClientCredentialsAsync(client.ClientId, secret))).GetProperty("access_token").GetString()!;
        fixture.Clock!.Advance(TimeSpan.FromSeconds(200));
        var result = await OAuthTestClient.JsonAsync(await c.PostFormAsync("/oauth2/introspect", OAuthTestClient.Form(("token", token)), (api.ClientId, apiSecret)));
        Assert.False(result.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task Expired_client_assertion_and_expired_secret_are_rejected()
    {
        using var c = NewClient();
        var (pk, key) = await c.PrivateKeyJwtClientAsync();
        var old = c.ClientAssertion(pk.ClientId, key, now: fixture.Clock!.GetUtcNow().UtcDateTime.AddMinutes(-10));
        var response = await c.PostFormAsync("/oauth2/token", OAuthTestClient.Form(("grant_type", "client_credentials"),
            ("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"), ("client_assertion", old)));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var secret = RandomTokens.CreateClientSecret();
        var client = new ClientApplication
        {
            ClientId = OAuthTestClient.Unique("expiring"),
            ClientName = "Expiring",
            ClientType = ClientType.Confidential,
            TokenEndpointAuthMethod = ClientAuthMethods.SecretBasic,
            AllowedGrantTypes = [GrantTypes.ClientCredentials],
            RedirectUris = [],
            AllowedScopes = ["erp.read"],
            Secrets = [new ClientSecretInfo(0, TokenHasher.Hash(secret), null, fixture.Clock.GetUtcNow(), fixture.Clock.GetUtcNow().AddHours(1))],
        };
        await fixture.SeedClientAsync(client);
        Assert.Equal(HttpStatusCode.OK, (await c.ClientCredentialsAsync(client.ClientId, secret)).StatusCode);
        fixture.Clock.Advance(TimeSpan.FromHours(2));
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.ClientCredentialsAsync(client.ClientId, secret)).StatusCode);
    }

    [Fact]
    public async Task Lockout_ends_after_the_configured_time()
    {
        using var c = NewClient();
        var spa = await c.PublicClientAsync();
        var user = await c.UserAsync();
        var url = c.AuthorizeUrl(spa.ClientId, OAuthTestClient.NewVerifier());
        for (var i = 0; i < AuthServerFixture.MaxFailedAttempts; i++)
            await c.SubmitLoginAsync(await c.GetLoginPageAsync(url), user.LoginName, "wrong");

        Assert.Equal(HttpStatusCode.BadRequest, (await c.SubmitLoginAsync(await c.GetLoginPageAsync(url), user.LoginName, user.Password)).StatusCode);
        fixture.Clock!.Advance(TimeSpan.FromSeconds(301));
        Assert.Equal(HttpStatusCode.SeeOther, (await c.SubmitLoginAsync(await c.GetLoginPageAsync(url), user.LoginName, user.Password)).StatusCode);
    }
}

public sealed class InMemoryClockTests(InMemoryFixture fixture) : ClockTests<InMemoryFixture>(fixture);

public sealed class SqlServerClockTests(SqlServerFixture fixture) : ClockTests<SqlServerFixture>(fixture);
