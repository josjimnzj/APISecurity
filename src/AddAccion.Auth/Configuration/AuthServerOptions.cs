namespace AddAccion.Auth.Configuration;

/// <summary>Root configuration section "Auth". Validated at startup (fail fast).</summary>
public sealed class AuthServerOptions
{
    public const string SectionName = "Auth";

    /// <summary>Public issuer identifier, e.g. https://auth.addaccion.com. Never derived from the Host header.</summary>
    public string Issuer { get; set; } = "";

    /// <summary>Reject plain HTTP requests (after X-Forwarded-Proto processing). Health probes are exempt.</summary>
    public bool RequireHttps { get; set; } = true;

    public SigningKeyOptions SigningKeys { get; set; } = new();
    public TokenOptions Tokens { get; set; } = new();
    public LoginOptions Login { get; set; } = new();
    public CachingOptions Caching { get; set; } = new();
    public RateLimitOptions RateLimits { get; set; } = new();
    public CorsOptions Cors { get; set; } = new();
    public UserStoreOptions Users { get; set; } = new();
    public ProxyOptions Proxy { get; set; } = new();
    public CleanupOptions Cleanup { get; set; } = new();
}

public sealed class SigningKeyOptions
{
    /// <summary>Directory with PKCS#8 PEM private keys (RSA >= 2048 or EC P-256/P-384/P-521). Mounted as a secret.</summary>
    public string? Path { get; set; }

    /// <summary>
    /// Keys supplied inline (environment variables / platform secrets) instead of files, each as PEM or base64 of the PEM.
    /// Named "inline-0", "inline-1"…; "inline-0" signs unless <see cref="ActiveKey"/> says otherwise.
    /// Used on platforms without reliable secret volumes (e.g. Render). Mutually exclusive with <see cref="Path"/>.
    /// </summary>
    public string[] Inline { get; set; } = [];

    /// <summary>File name (inside <see cref="Path"/>) or "inline-N" of the key used to sign. Other keys are published for validation only.</summary>
    public string? ActiveKey { get; set; }

    /// <summary>Development only: generate an ephemeral in-memory key when no key directory is configured.</summary>
    public bool AllowEphemeralDevelopmentKey { get; set; }
}

public sealed class TokenOptions
{
    public int AuthorizationCodeLifetimeSeconds { get; set; } = 60;
    public int IdTokenLifetimeSeconds { get; set; } = 300;
    public int ClientAssertionMaxLifetimeSeconds { get; set; } = 300;
    public int ClockSkewSeconds { get; set; } = 30;
}

public sealed class LoginOptions
{
    public int MaxFailedAttempts { get; set; } = 5;
    public int LockoutSeconds { get; set; } = 900;

    /// <summary>Base64 key (>= 32 bytes) for the signed double-submit CSRF token of the login form. Required outside Development.</summary>
    public string? CsrfKey { get; set; }

    /// <summary>Maximum concurrent password hash verifications per instance (PBKDF2 is CPU bound). 0 = processor count.</summary>
    public int MaxConcurrentPasswordVerifications { get; set; }

    /// <summary>Text shown in the login page header.</summary>
    public string BrandName { get; set; } = "AddACCION";
}

public sealed class CachingOptions
{
    public int ClientCacheSeconds { get; set; } = 60;
    public int ScopeCacheSeconds { get; set; } = 120;
}

public sealed class RateLimitOptions
{
    public bool Enabled { get; set; } = true;
    /// <summary>Token bucket per client IP for /oauth2/token, /introspect, /revoke.</summary>
    public int TokenBurst { get; set; } = 100;
    public int TokenPerSecond { get; set; } = 50;
    /// <summary>Fixed window per client IP for login form submissions.</summary>
    public int LoginPermitsPerWindow { get; set; } = 10;
    public int LoginWindowSeconds { get; set; } = 60;
}

public sealed class CorsOptions
{
    /// <summary>Origins of browser apps (SPA) allowed to call token/revoke/userinfo. Exact origins, no wildcards.</summary>
    public string[] AllowedOrigins { get; set; } = [];
}

public sealed class UserStoreOptions
{
    /// <summary>Send LoginName/UserId parameters as varchar instead of nvarchar (when the base columns are varchar) to keep index seeks.</summary>
    public bool UseVarcharParameters { get; set; }
}

public sealed class ProxyOptions
{
    /// <summary>CIDR networks of trusted reverse proxies / ingress controllers whose X-Forwarded-* headers are honoured.</summary>
    public string[] KnownNetworks { get; set; } = [];
    public string[] KnownProxies { get; set; } = [];

    /// <summary>
    /// Accept X-Forwarded-Proto/For from any peer. Only for platforms where the container is reachable exclusively
    /// through the platform load balancer (Render, Cloud Run, App Service). Only the last hop is used.
    /// </summary>
    public bool TrustAllProxies { get; set; }

    /// <summary>
    /// Header carrying the real client IP set by the edge (e.g. "CF-Connecting-IP" behind Cloudflare/Render).
    /// Used for per-IP rate limiting and audit logs. Only safe when the edge always overwrites it.
    /// </summary>
    public string? ClientIpHeader { get; set; }
    /// <summary>Optional path prefix when the issuer contains a path (e.g. /auth).</summary>
    public string? PathBase { get; set; }
}

public sealed class CleanupOptions
{
    public bool Enabled { get; set; } = true;
    public int IntervalSeconds { get; set; } = 900;
    public int BatchSize { get; set; } = 5000;
}
