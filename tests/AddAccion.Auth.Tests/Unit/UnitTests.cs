using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AddAccion.Auth.Configuration;
using AddAccion.Auth.Crypto;
using AddAccion.Auth.Domain;
using AddAccion.Auth.Endpoints;
using AddAccion.Auth.Persistence;
using AddAccion.Auth.Protocol;
using AddAccion.Auth.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AddAccion.Auth.Tests.Unit;

public sealed class PkceTests
{
    [Fact]
    public void S256_matches_rfc7636_appendix_b() =>
        Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Pkce.S256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));

    [Theory]
    [InlineData("short", false)]
    [InlineData("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", true)]
    [InlineData("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX+", false)]
    public void Verifier_format(string verifier, bool valid) => Assert.Equal(valid, Pkce.IsValidVerifier(verifier));
}

public sealed class PasswordHashTests
{
    private readonly IdentityPasswordHashVerifier _verifier = new();

    [Fact]
    public void Verifies_hashes_produced_by_aspnetcore_identity_v3()
    {
        var hash = new PasswordHasher<object>().HashPassword(new object(), "S3guro!ñ");
        Assert.Equal(PasswordCheck.Success, _verifier.Verify(hash, "S3guro!ñ"));
        Assert.Equal(PasswordCheck.Failed, _verifier.Verify(hash, "S3guro!n"));
    }

    [Fact]
    public void Accepts_legacy_v2_but_flags_it_as_weak()
    {
        var options = Options.Create(new PasswordHasherOptions { CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV2 });
        var hash = new PasswordHasher<object>(options).HashPassword(new object(), "legacy");
        Assert.Equal(PasswordCheck.SuccessWeakHash, _verifier.Verify(hash, "legacy"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-base64!!")]
    [InlineData("AgAAAA==")]
    public void Malformed_hashes_fail_closed(string? hash) => Assert.Equal(PasswordCheck.Failed, _verifier.Verify(hash, "x"));
}

public sealed class RedirectUriTests
{
    [Theory]
    [InlineData("https://app.addaccion.com/cb", true)]
    [InlineData("http://127.0.0.1/cb", true)]
    [InlineData("http://[::1]:8080/cb", true)]
    [InlineData("com.addaccion.app:/oauth", true)]
    [InlineData("http://app.addaccion.com/cb", false)]
    [InlineData("http://localhost/cb", false)]
    [InlineData("https://*.addaccion.com/cb", false)]
    [InlineData("https://app.addaccion.com/cb#frag", false)]
    [InlineData("https://user:pw@app.addaccion.com/cb", false)]
    [InlineData("javascript:alert(1)", false)]
    [InlineData("/relative", false)]
    public void Registration_rules(string uri, bool valid) => Assert.Equal(valid, RedirectUris.IsValidForRegistration(uri, out _));

    [Fact]
    public void Matching_is_exact_except_loopback_port()
    {
        string[] registered = ["https://app.addaccion.com/cb", "http://127.0.0.1/native"];
        Assert.True(RedirectUris.Matches(registered, "https://app.addaccion.com/cb"));
        Assert.False(RedirectUris.Matches(registered, "https://app.addaccion.com/cb/"));
        Assert.False(RedirectUris.Matches(registered, "https://APP.addaccion.com/cb"));
        Assert.False(RedirectUris.Matches(registered, "https://app.addaccion.com/cb?x=1"));
        Assert.True(RedirectUris.Matches(registered, "http://127.0.0.1:49152/native"));
        Assert.False(RedirectUris.Matches(registered, "http://127.0.0.1:49152/other"));
    }

    [Fact]
    public void AppendQuery_preserves_existing_query_and_encodes() =>
        Assert.Equal("https://a.test/cb?x=1&code=a%2Bb&state=s%20t",
            RedirectUris.AppendQuery("https://a.test/cb?x=1", [new("code", "a+b"), new("state", "s t"), new("iss", null)]));
}

public sealed class ScopeAndBasicAuthTests
{
    [Fact]
    public void Scope_parser_dedupes_and_rejects_invalid_characters()
    {
        Assert.True(ScopeParser.TryParse("openid  erp.read openid", out var scopes));
        Assert.Equal(["openid", "erp.read"], scopes);
        Assert.False(ScopeParser.TryParse("bad\"scope", out _));
        Assert.False(ScopeParser.TryParse("tab\tscope", out _));
    }

    [Fact]
    public void Basic_credentials_are_form_url_decoded()
    {
        var raw = Convert.ToBase64String(Encoding.UTF8.GetBytes("my%3Aclient:p%40ss+word"));
        Assert.True(ClientAuthenticator.TryParseBasic(raw, out var id, out var secret));
        Assert.Equal("my:client", id);
        Assert.Equal("p@ss word", secret);
        Assert.False(ClientAuthenticator.TryParseBasic("@@@", out _, out _));
        Assert.False(ClientAuthenticator.TryParseBasic(Convert.ToBase64String("nocolon"u8.ToArray()), out _, out _));
    }

    [Fact]
    public void Token_hashing_is_constant_time_compare_of_sha256()
    {
        var secret = RandomTokens.CreateClientSecret();
        Assert.StartsWith("aasec_", secret);
        Assert.True(TokenHasher.Matches(secret, TokenHasher.Hash(secret)));
        Assert.False(TokenHasher.Matches(secret + "x", TokenHasher.Hash(secret)));
        Assert.Equal(43, RandomTokens.Create(32).Length);
    }
}

public sealed class KeyAndJwksTests
{
    [Fact]
    public void Kid_is_rfc7638_thumbprint_for_rsa_and_ec()
    {
        foreach (var type in new[] { "rsa", "ec" })
        {
            var key = SigningKeyStore.FromPem(SigningKeyStore.GeneratePem(type));
            Assert.Equal(Base64UrlEncoder.Encode(key.PublicJwk.ComputeJwkThumbprint()), key.KeyId);
            Assert.True(string.IsNullOrEmpty(key.PublicJwk.D));
        }
    }

    [Fact]
    public void Small_rsa_keys_are_refused()
    {
        using var rsa = RSA.Create(1024);
        Assert.Throws<InvalidOperationException>(() => SigningKeyStore.FromAlgorithm(rsa));
    }

    [Fact]
    public void Client_jwks_rejects_symmetric_private_and_weak_keys()
    {
        Assert.False(ClientJwks.TryParse("""{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}""", out _, out _));
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = ec.ExportParameters(true);
        var priv = $$"""{"keys":[{"kty":"EC","crv":"P-256","x":"{{Base64UrlEncoder.Encode(p.Q.X)}}","y":"{{Base64UrlEncoder.Encode(p.Q.Y)}}","d":"{{Base64UrlEncoder.Encode(p.D)}}"}]}""";
        Assert.False(ClientJwks.TryParse(priv, out _, out var error));
        Assert.Contains("private", error);
        var pub = $$"""{"keys":[{"kty":"EC","crv":"P-256","x":"{{Base64UrlEncoder.Encode(p.Q.X)}}","y":"{{Base64UrlEncoder.Encode(p.Q.Y)}}"}]}""";
        Assert.True(ClientJwks.TryParse(pub, out var keys, out _));
        Assert.Single(keys);
        Assert.False(ClientJwks.TryParse("not json", out _, out _));
    }
}

public sealed class ClientRegistrationTests
{
    private static readonly ScopeSnapshot Scopes = new([new ScopeDefinition("erp.read", "https://erp", null, true)], DateTimeOffset.MaxValue);

    [Fact]
    public void Confidential_client_gets_a_hashed_secret()
    {
        var (client, secret, error) = ClientRegistration.Build(new CreateClientRequest
        {
            ClientId = "erp-sync",
            ClientName = "ERP",
            ClientType = "confidential",
            GrantTypes = ["client_credentials"],
            Scopes = ["erp.read"],
        }, Scopes, DateTimeOffset.UtcNow);
        Assert.Null(error);
        Assert.NotNull(secret);
        Assert.True(TokenHasher.Matches(secret, client!.Secrets.Single().SecretHash));
        Assert.Equal(ClientAuthMethods.SecretBasic, client.TokenEndpointAuthMethod);
    }

    [Theory]
    [InlineData("""{"client_id":"a","client_name":"n","client_type":"confidential","grant_types":["client_credentials"],"scopes":["erp.read"]}""")]
    [InlineData("""{"client_id":"spa-1","client_name":"n","client_type":"public","grant_types":["refresh_token"],"scopes":["openid"]}""")]
    [InlineData("""{"client_id":"svc-1","client_name":"n","client_type":"confidential","grant_types":["client_credentials"],"scopes":["openid"]}""")]
    [InlineData("""{"client_id":"svc-2","client_name":"n","client_type":"confidential","grant_types":["client_credentials"],"scopes":["unknown"]}""")]
    [InlineData("""{"client_id":"svc-3","client_name":"n","client_type":"confidential","token_endpoint_auth_method":"none","grant_types":["client_credentials"],"scopes":["erp.read"]}""")]
    [InlineData("""{"client_id":"svc-4","client_name":"n","client_type":"confidential","grant_types":["client_credentials"],"scopes":["erp.read"],"access_token_lifetime":999999}""")]
    public void Invalid_metadata_is_rejected(string json)
    {
        var request = JsonSerializer.Deserialize(json, AddAccion.Auth.Hosting.AuthJsonContext.Default.CreateClientRequest)!;
        var (client, _, error) = ClientRegistration.Build(request, Scopes, DateTimeOffset.UtcNow);
        Assert.Null(client);
        Assert.NotNull(error);
    }
}

public sealed class OptionsValidationTests
{
    private sealed class Env(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "test";
        public string ContentRootPath { get; set; } = "/";
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }

    [Fact]
    public void Production_requires_https_issuer_keys_and_csrf_key()
    {
        var validator = new AuthServerOptionsValidator(new Env("Production"));
        var result = validator.Validate(null, new AuthServerOptions { Issuer = "http://auth.addaccion.com/" });
        Assert.True(result.Failed);
        var text = string.Join('\n', result.Failures!);
        Assert.Contains("https", text);
        Assert.Contains("SigningKeys:Path", text);
        Assert.Contains("CsrfKey", text);
        Assert.Contains("end with '/'", text);

        var ok = validator.Validate(null, new AuthServerOptions
        {
            Issuer = "https://auth.addaccion.com",
            SigningKeys = new SigningKeyOptions { Path = "/keys" },
            Login = new LoginOptions { CsrfKey = Convert.ToBase64String(new byte[32]) },
        });
        Assert.True(ok.Succeeded);
    }

    [Fact]
    public void Wildcard_cors_origin_is_rejected()
    {
        var result = new AuthServerOptionsValidator(new Env("Development")).Validate(null, new AuthServerOptions
        {
            Issuer = "https://auth.addaccion.com",
            SigningKeys = new SigningKeyOptions { AllowEphemeralDevelopmentKey = true },
            Cors = new CorsOptions { AllowedOrigins = ["https://*.addaccion.com"] },
        });
        Assert.True(result.Failed);
    }
}
