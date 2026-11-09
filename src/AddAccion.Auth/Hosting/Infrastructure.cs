using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using AddAccion.Auth.Endpoints;
using AddAccion.Auth.Protocol;

namespace AddAccion.Auth.Hosting;

[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(OAuthErrorResponse))]
[JsonSerializable(typeof(TokenResponse))]
[JsonSerializable(typeof(IntrospectionResponse))]
[JsonSerializable(typeof(CreateClientRequest))]
[JsonSerializable(typeof(CreateSecretRequest))]
[JsonSerializable(typeof(ClientView))]
[JsonSerializable(typeof(CreatedSecretView))]
[JsonSerializable(typeof(string))]
public sealed partial class AuthJsonContext : JsonSerializerContext;

/// <summary>Low-cardinality counters (Meter "AddAccion.Auth"), exportable with OpenTelemetry or dotnet-counters.</summary>
public sealed class AuthMetrics : IDisposable
{
    public const string MeterName = "AddAccion.Auth";

    private readonly Meter _meter;
    private readonly Counter<long> _tokensIssued;
    private readonly Counter<long> _tokenErrors;
    private readonly Counter<long> _logins;
    private readonly Counter<long> _authorizeErrors;
    private readonly Counter<long> _securityEvents;
    private readonly Counter<long> _introspections;

    public AuthMetrics(IMeterFactory factory)
    {
        _meter = factory.Create(MeterName);
        _tokensIssued = _meter.CreateCounter<long>("auth.tokens.issued");
        _tokenErrors = _meter.CreateCounter<long>("auth.tokens.errors");
        _logins = _meter.CreateCounter<long>("auth.logins");
        _authorizeErrors = _meter.CreateCounter<long>("auth.authorize.errors");
        _securityEvents = _meter.CreateCounter<long>("auth.security.events");
        _introspections = _meter.CreateCounter<long>("auth.introspections");
    }

    public void TokenIssued(string grant) => _tokensIssued.Add(1, new KeyValuePair<string, object?>("grant_type", grant));

    public void TokenFailed(string grant, string error) =>
        _tokenErrors.Add(1, new KeyValuePair<string, object?>("grant_type", grant), new KeyValuePair<string, object?>("error", error));

    public void LoginSucceeded() => _logins.Add(1, new KeyValuePair<string, object?>("result", "success"));

    public void LoginFailed(string reason) =>
        _logins.Add(1, new KeyValuePair<string, object?>("result", "failure"), new KeyValuePair<string, object?>("reason", reason));

    public void AuthorizeFailed(string error) => _authorizeErrors.Add(1, new KeyValuePair<string, object?>("error", error));

    public void SecurityEvent(string kind) => _securityEvents.Add(1, new KeyValuePair<string, object?>("kind", kind));

    public void Introspection() => _introspections.Add(1);

    public void Dispose() => _meter.Dispose();
}

internal static class LogRedaction
{
    /// <summary>Short irreversible fingerprint: correlates failures for one login name without logging it (it may be a mistyped password).</summary>
    public static string Fingerprint(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)).AsSpan(0, 6));
}

/// <summary>
/// Security audit events (OWASP Logging Cheat Sheet): who, what, outcome. Never logs passwords,
/// secrets, codes or tokens; jti identifies a token without exposing it.
/// </summary>
internal static partial class Log
{
    [LoggerMessage(1001, LogLevel.Information, "Token issued grant={GrantType} client={ClientId} sub={Subject} jti={Jti}")]
    public static partial void TokenIssued(ILogger logger, string grantType, string clientId, string subject, string jti);

    [LoggerMessage(1002, LogLevel.Warning, "Client authentication failed method={Method} reason={Reason} ip={ClientIp}")]
    public static partial void ClientAuthFailed(ILogger logger, string method, string reason, string clientIp);

    [LoggerMessage(1003, LogLevel.Warning, "Authorization code replay detected client={ClientId}; issued tokens revoked")]
    public static partial void CodeReplay(ILogger logger, string clientId);

    [LoggerMessage(1004, LogLevel.Warning, "Refresh token family revoked reason={Reason} client={ClientId} sub={Subject} count={Count}")]
    public static partial void RefreshFamilyRevoked(ILogger logger, string reason, string clientId, string subject, int count);

    [LoggerMessage(1005, LogLevel.Information, "Token revoked type={TokenType} client={ClientId}")]
    public static partial void TokenRevoked(ILogger logger, string tokenType, string clientId);

    [LoggerMessage(2001, LogLevel.Information, "Login succeeded sub={Subject} client={ClientId} ip={ClientIp}")]
    public static partial void LoginSucceeded(ILogger logger, string subject, string clientId, string clientIp);

    [LoggerMessage(2002, LogLevel.Warning, "Login failed sub={Subject} reason={Reason} ip={ClientIp}")]
    public static partial void LoginFailed(ILogger logger, string subject, string reason, string clientIp);

    [LoggerMessage(2003, LogLevel.Warning, "Login failed for unknown login fingerprint={Fingerprint} ip={ClientIp}")]
    public static partial void LoginFailedUnknownUser(ILogger logger, string fingerprint, string clientIp);

    [LoggerMessage(2004, LogLevel.Warning, "User {Subject} has a weak password hash (legacy format or low iteration count); rehash it in the user store")]
    public static partial void WeakPasswordHash(ILogger logger, string subject);

    [LoggerMessage(3001, LogLevel.Information, "Admin action actor={Actor} action={Action} client={ClientId}")]
    public static partial void AdminAction(ILogger logger, string actor, string action, string clientId);

    [LoggerMessage(4001, LogLevel.Information, "Cleanup removed {Count} expired rows")]
    public static partial void CleanupCompleted(ILogger logger, int count);

    [LoggerMessage(4002, LogLevel.Error, "Cleanup failed")]
    public static partial void CleanupFailed(ILogger logger, Exception exception);

    [LoggerMessage(4101, LogLevel.Warning, "Using an EPHEMERAL development signing key. Tokens become invalid on restart.")]
    public static partial void EphemeralSigningKey(ILogger logger);

    [LoggerMessage(4102, LogLevel.Information, "Loaded signing key {File} kid={KeyId} alg={Algorithm}")]
    public static partial void SigningKeyLoaded(ILogger logger, string file, string keyId, string algorithm);

    [LoggerMessage(5001, LogLevel.Error, "Unhandled exception processing {Path}")]
    public static partial void Unhandled(ILogger logger, Exception exception, string path);

    [LoggerMessage(5002, LogLevel.Warning, "Auth:RequireHttps is false outside Development. Only acceptable behind a TLS-terminating proxy that cannot forward X-Forwarded-Proto.")]
    public static partial void HttpsDisabled(ILogger logger);
}
