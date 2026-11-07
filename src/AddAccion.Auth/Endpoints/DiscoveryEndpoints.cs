using System.Text.Json;
using AddAccion.Auth.Configuration;
using AddAccion.Auth.Crypto;
using AddAccion.Auth.Protocol;
using Microsoft.Extensions.Options;

namespace AddAccion.Auth.Endpoints;

public static class Routes
{
    public const string Discovery = "/.well-known/openid-configuration";
    public const string OAuthMetadata = "/.well-known/oauth-authorization-server";
    public const string Jwks = "/.well-known/jwks.json";
    public const string Authorize = "/oauth2/authorize";
    public const string Token = "/oauth2/token";
    public const string Introspect = "/oauth2/introspect";
    public const string Revoke = "/oauth2/revoke";
    public const string UserInfo = "/oauth2/userinfo";
    public const string Admin = "/admin/v1";
    public const string HealthLive = "/health/live";
    public const string HealthReady = "/health/ready";
}

/// <summary>OIDC Discovery / RFC 8414 metadata and the JWKS, pre-serialized once (served from memory).</summary>
public sealed class DiscoveryDocument
{
    public byte[] Json { get; }

    public DiscoveryDocument(IOptions<AuthServerOptions> options, SigningKeyStore keys)
    {
        var issuer = options.Value.Issuer;
        string[] authMethods = ["client_secret_basic", "client_secret_post", "private_key_jwt"];
        string[] assertionAlgs = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"];

        using var stream = new MemoryStream();
        using (var w = new Utf8JsonWriter(stream))
        {
            w.WriteStartObject();
            w.WriteString("issuer", issuer);
            w.WriteString("authorization_endpoint", issuer + Routes.Authorize);
            w.WriteString("token_endpoint", issuer + Routes.Token);
            w.WriteString("jwks_uri", issuer + Routes.Jwks);
            w.WriteString("userinfo_endpoint", issuer + Routes.UserInfo);
            w.WriteString("introspection_endpoint", issuer + Routes.Introspect);
            w.WriteString("revocation_endpoint", issuer + Routes.Revoke);
            Array(w, "scopes_supported", StandardScopes.Identity);
            Array(w, "response_types_supported", ["code"]);
            Array(w, "response_modes_supported", ["query"]);
            Array(w, "grant_types_supported", ["authorization_code", "refresh_token", "client_credentials"]);
            Array(w, "subject_types_supported", ["public"]);
            Array(w, "id_token_signing_alg_values_supported", keys.Algorithms);
            Array(w, "token_endpoint_auth_methods_supported", [.. authMethods, "none"]);
            Array(w, "token_endpoint_auth_signing_alg_values_supported", assertionAlgs);
            Array(w, "introspection_endpoint_auth_methods_supported", authMethods);
            Array(w, "introspection_endpoint_auth_signing_alg_values_supported", assertionAlgs);
            Array(w, "revocation_endpoint_auth_methods_supported", [.. authMethods, "none"]);
            Array(w, "revocation_endpoint_auth_signing_alg_values_supported", assertionAlgs);
            Array(w, "code_challenge_methods_supported", ["S256"]);
            Array(w, "claims_supported",
                ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "given_name", "family_name", "preferred_username", "email", "email_verified", "roles"]);
            Array(w, "prompt_values_supported", ["none", "login"]);
            w.WriteBoolean("authorization_response_iss_parameter_supported", true);
            w.WriteBoolean("request_parameter_supported", false);
            w.WriteBoolean("request_uri_parameter_supported", false);
            w.WriteBoolean("claims_parameter_supported", false);
            w.WriteEndObject();
        }
        Json = stream.ToArray();
    }

    private static void Array(Utf8JsonWriter w, string name, IEnumerable<string> values)
    {
        w.WriteStartArray(name);
        foreach (var v in values) w.WriteStringValue(v);
        w.WriteEndArray();
    }
}
