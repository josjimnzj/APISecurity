using Microsoft.Extensions.Options;

namespace AddAccion.Auth.Configuration;

internal sealed class AuthServerOptionsValidator(IHostEnvironment environment) : IValidateOptions<AuthServerOptions>
{
    public ValidateOptionsResult Validate(string? name, AuthServerOptions options)
    {
        var errors = new List<string>();
        var isDev = environment.IsDevelopment();

        if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out var issuer))
        {
            errors.Add("Auth:Issuer must be an absolute URI.");
        }
        else
        {
            if (!string.IsNullOrEmpty(issuer.Query) || !string.IsNullOrEmpty(issuer.Fragment))
                errors.Add("Auth:Issuer must not contain query or fragment.");
            if (options.Issuer.EndsWith('/'))
                errors.Add("Auth:Issuer must not end with '/'.");
            if (issuer.Scheme != Uri.UriSchemeHttps && options.RequireHttps)
                errors.Add("Auth:Issuer must use https when Auth:RequireHttps is true.");
        }

        var hasPath = !string.IsNullOrWhiteSpace(options.SigningKeys.Path);
        var hasInline = options.SigningKeys.Inline.Any(k => !string.IsNullOrWhiteSpace(k));
        if (hasPath && hasInline)
            errors.Add("Use either Auth:SigningKeys:Path or Auth:SigningKeys:Inline, not both.");
        if (!hasPath && !hasInline && !(isDev && options.SigningKeys.AllowEphemeralDevelopmentKey))
            errors.Add("Auth:SigningKeys:Path or Auth:SigningKeys:Inline is required (ephemeral keys are only allowed in Development).");
        if (options.Proxy.ClientIpHeader is { Length: > 0 } header && (header.Length > 64 || header.Any(c => !(char.IsAsciiLetterOrDigit(c) || c == '-'))))
            errors.Add("Auth:Proxy:ClientIpHeader must be a header name.");

        if (string.IsNullOrWhiteSpace(options.Login.CsrfKey))
        {
            if (!isDev) errors.Add("Auth:Login:CsrfKey is required outside Development.");
        }
        else if (!IsBase64OfAtLeast(options.Login.CsrfKey, 32))
        {
            errors.Add("Auth:Login:CsrfKey must be base64 of at least 32 bytes.");
        }

        var t = options.Tokens;
        if (t.AuthorizationCodeLifetimeSeconds is < 10 or > 600) errors.Add("Auth:Tokens:AuthorizationCodeLifetimeSeconds must be 10..600.");
        if (t.IdTokenLifetimeSeconds is < 60 or > 3600) errors.Add("Auth:Tokens:IdTokenLifetimeSeconds must be 60..3600.");
        if (t.ClientAssertionMaxLifetimeSeconds is < 30 or > 3600) errors.Add("Auth:Tokens:ClientAssertionMaxLifetimeSeconds must be 30..3600.");
        if (t.ClockSkewSeconds is < 0 or > 300) errors.Add("Auth:Tokens:ClockSkewSeconds must be 0..300.");

        if (options.Login.MaxFailedAttempts is < 1 or > 100) errors.Add("Auth:Login:MaxFailedAttempts must be 1..100.");
        if (options.Login.LockoutSeconds is < 1 or > 86400) errors.Add("Auth:Login:LockoutSeconds must be 1..86400.");

        foreach (var origin in options.Cors.AllowedOrigins)
        {
            if (origin.Contains('*', StringComparison.Ordinal) || !Uri.TryCreate(origin, UriKind.Absolute, out var o) || o.AbsolutePath != "/" || origin.EndsWith('/'))
                errors.Add($"Auth:Cors:AllowedOrigins contains an invalid origin '{origin}' (exact scheme://host[:port], no wildcard, no path).");
        }

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }

    private static bool IsBase64OfAtLeast(string value, int bytes)
    {
        var buffer = new byte[value.Length];
        return Convert.TryFromBase64String(value, buffer, out var written) && written >= bytes;
    }
}
