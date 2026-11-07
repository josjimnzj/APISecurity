using System.Text.Json.Serialization;
using Microsoft.Extensions.Primitives;

namespace AddAccion.Auth.Protocol;

public static class OAuthErrors
{
    public const string InvalidRequest = "invalid_request";
    public const string InvalidClient = "invalid_client";
    public const string InvalidGrant = "invalid_grant";
    public const string UnauthorizedClient = "unauthorized_client";
    public const string UnsupportedGrantType = "unsupported_grant_type";
    public const string UnsupportedResponseType = "unsupported_response_type";
    public const string InvalidScope = "invalid_scope";
    public const string AccessDenied = "access_denied";
    public const string ServerError = "server_error";
    public const string TemporarilyUnavailable = "temporarily_unavailable";
    public const string LoginRequired = "login_required";
    public const string RequestNotSupported = "request_not_supported";
    public const string RequestUriNotSupported = "request_uri_not_supported";
    public const string InvalidToken = "invalid_token";
    public const string InsufficientScope = "insufficient_scope";
}

public static class StandardScopes
{
    public const string OpenId = "openid";
    public const string Profile = "profile";
    public const string Email = "email";
    public const string Roles = "roles";
    public const string OfflineAccess = "offline_access";

    public static readonly string[] Identity = [OpenId, Profile, Email, Roles, OfflineAccess];

    public static bool IsIdentityScope(string scope) => Array.IndexOf(Identity, scope) >= 0;
}

/// <summary>
/// Request parameters (query or form). Implements RFC 6749 §3.1: parameters without value are treated as
/// omitted and parameters MUST NOT be included more than once.
/// </summary>
public sealed class RequestParameters
{
    private readonly Func<string, StringValues> _get;

    public string? DuplicateParameter { get; }

    private RequestParameters(IEnumerable<KeyValuePair<string, StringValues>> values, Func<string, StringValues> get)
    {
        _get = get;
        foreach (var (key, value) in values)
        {
            if (value.Count > 1)
            {
                DuplicateParameter = key;
                break;
            }
        }
    }

    public static RequestParameters FromQuery(IQueryCollection query) => new(query, k => query[k]);

    public static RequestParameters FromForm(IFormCollection form) => new(form, k => form[k]);

    public string? this[string name]
    {
        get
        {
            var v = _get(name);
            return v.Count == 1 && !string.IsNullOrEmpty(v[0]) ? v[0] : null;
        }
    }
}

public static class ScopeParser
{
    public const int MaxScopes = 50;
    public const int MaxScopeLength = 200;

    /// <summary>Parses a space-delimited scope string (RFC 6749 §3.3). Null/empty input yields an empty list.</summary>
    public static bool TryParse(string? value, out IReadOnlyList<string> scopes)
    {
        scopes = [];
        if (string.IsNullOrEmpty(value)) return true;
        if (value.Length > MaxScopes * (MaxScopeLength + 1)) return false;

        var result = new List<string>();
        foreach (var token in value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (token.Length > MaxScopeLength) return false;
            foreach (var c in token)
            {
                // scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
                if (c < 0x21 || c > 0x7E || c == '"' || c == '\\') return false;
            }
            if (!result.Contains(token, StringComparer.Ordinal)) result.Add(token);
            if (result.Count > MaxScopes) return false;
        }
        scopes = result;
        return true;
    }

    public static string Join(IEnumerable<string> scopes) => string.Join(' ', scopes);

    public static bool Contains(IReadOnlyList<string> scopes, string scope)
    {
        foreach (var s in scopes)
        {
            if (string.Equals(s, scope, StringComparison.Ordinal)) return true;
        }
        return false;
    }
}

public sealed record OAuthErrorResponse(
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("error_description")] string? ErrorDescription = null);

public sealed record TokenResponse
{
    [JsonPropertyName("access_token")] public required string AccessToken { get; init; }
    [JsonPropertyName("token_type")] public string TokenType { get; init; } = "Bearer";
    [JsonPropertyName("expires_in")] public required int ExpiresIn { get; init; }
    [JsonPropertyName("scope")] public string? Scope { get; init; }
    [JsonPropertyName("refresh_token")] public string? RefreshToken { get; init; }
    [JsonPropertyName("id_token")] public string? IdToken { get; init; }
}

public sealed record IntrospectionResponse
{
    [JsonPropertyName("active")] public required bool Active { get; init; }
    [JsonPropertyName("scope")] public string? Scope { get; init; }
    [JsonPropertyName("client_id")] public string? ClientId { get; init; }
    [JsonPropertyName("username")] public string? Username { get; init; }
    [JsonPropertyName("token_type")] public string? TokenType { get; init; }
    [JsonPropertyName("exp")] public long? Exp { get; init; }
    [JsonPropertyName("iat")] public long? Iat { get; init; }
    [JsonPropertyName("sub")] public string? Sub { get; init; }
    [JsonPropertyName("aud")] public IReadOnlyList<string>? Aud { get; init; }
    [JsonPropertyName("iss")] public string? Iss { get; init; }
    [JsonPropertyName("jti")] public string? Jti { get; init; }
    [JsonPropertyName("roles")] public IReadOnlyList<string>? Roles { get; init; }

    public static readonly IntrospectionResponse Inactive = new() { Active = false };
}
