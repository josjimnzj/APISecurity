using System.Net;
using System.Threading.RateLimiting;
using AddAccion.Auth.Configuration;
using AddAccion.Auth.Crypto;
using AddAccion.Auth.Endpoints;
using AddAccion.Auth.Persistence;
using AddAccion.Auth.Persistence.SqlServer;
using AddAccion.Auth.Protocol;
using AddAccion.Auth.Security;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;

namespace AddAccion.Auth.Hosting;

public static class AuthServer
{
    public const string ConnectionStringName = "AuthDb";

    public static WebApplication Build(string[] args)
    {
        var builder = WebApplication.CreateSlimBuilder(args);
        builder.WebHost.UseKestrelHttpsConfiguration();
        ConfigureServices(builder);
        var app = builder.Build();
        ConfigurePipeline(app);
        return app;
    }

    public static void ConfigureServices(WebApplicationBuilder builder)
    {
        var services = builder.Services;
        var config = builder.Configuration;
        var auth = config.GetSection(AuthServerOptions.SectionName).Get<AuthServerOptions>() ?? new AuthServerOptions();

        if (!builder.Environment.IsDevelopment())
        {
            builder.Logging.ClearProviders();
            builder.Logging.AddJsonConsole(o =>
            {
                o.UseUtcTimestamp = true;
                o.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";
                o.IncludeScopes = false;
            });
        }

        builder.WebHost.ConfigureKestrel(k =>
        {
            k.AddServerHeader = false;
            k.Limits.MaxRequestBodySize = 64 * 1024;
            k.Limits.MaxRequestHeadersTotalSize = 32 * 1024;
            k.Limits.MaxRequestLineSize = 16 * 1024;
            k.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(15);
        });

        services.AddOptions<AuthServerOptions>().Bind(config.GetSection(AuthServerOptions.SectionName)).ValidateOnStart();
        services.AddSingleton<IValidateOptions<AuthServerOptions>, AuthServerOptionsValidator>();

        services.Configure<FormOptions>(o =>
        {
            o.ValueCountLimit = 64;
            o.ValueLengthLimit = 16 * 1024;
            o.KeyLengthLimit = 256;
            o.MultipartBodyLengthLimit = 0;
        });
        services.ConfigureHttpJsonOptions(o => o.SerializerOptions.TypeInfoResolverChain.Insert(0, AuthJsonContext.Default));

        // Persistence (SQL Server). Resolved lazily so tests can swap stores without a connection string.
        services.AddSingleton(sp =>
        {
            var cs = sp.GetRequiredService<IConfiguration>().GetConnectionString(ConnectionStringName);
            if (string.IsNullOrWhiteSpace(cs)) throw new InvalidOperationException($"ConnectionStrings:{ConnectionStringName} is not configured.");
            return new SqlConnectionFactory(cs);
        });
        services.AddSingleton<IClientStore, SqlClientStore>();
        services.AddSingleton<IScopeStore, SqlScopeStore>();
        services.AddSingleton<IUserStore, SqlUserStore>();
        services.AddSingleton<IGrantStore, SqlGrantStore>();
        services.AddSingleton<IDatabaseHealth, SqlDatabaseHealth>();

        services.AddSingleton(TimeProvider.System);
        services.AddMemoryCache(o => o.SizeLimit = 50_000);
        services.AddMetrics();
        services.AddSingleton<AuthMetrics>();

        services.AddSingleton<SigningKeyStore>();
        services.AddSingleton<DiscoveryDocument>();
        services.AddSingleton<TokenService>();
        services.AddSingleton<AccessTokenValidator>();
        services.AddSingleton<ClientCatalog>();
        services.AddSingleton<ScopeCatalog>();
        services.AddSingleton<ClientAssertionValidator>();
        services.AddSingleton<ClientAuthenticator>();
        services.AddSingleton<IPasswordHashVerifier, IdentityPasswordHashVerifier>();
        services.AddSingleton<PasswordVerificationGate>();
        services.AddSingleton<CsrfProtector>();

        services.AddSingleton<TokenEndpoint>();
        services.AddSingleton<AuthorizeEndpoint>();
        services.AddSingleton<TokenManagementEndpoints>();
        services.AddSingleton<UserInfoEndpoint>();

        services.AddHostedService<CleanupService>();
        services.AddHealthChecks().AddCheck<DatabaseHealthCheck>("database", tags: ["ready"]);

        services.Configure<ForwardedHeadersOptions>(o =>
        {
            o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            o.ForwardLimit = 2;
            foreach (var network in auth.Proxy.KnownNetworks) o.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(network));
            foreach (var proxy in auth.Proxy.KnownProxies) o.KnownProxies.Add(IPAddress.Parse(proxy));
        });

        services.AddCors(o =>
        {
            o.AddPolicy("public", p => p.AllowAnyOrigin().WithMethods("GET").WithHeaders("Accept"));
            o.AddPolicy("spa", p =>
            {
                if (auth.Cors.AllowedOrigins.Length > 0)
                {
                    p.WithOrigins(auth.Cors.AllowedOrigins)
                     .WithMethods("GET", "POST")
                     .WithHeaders("Authorization", "Content-Type", "Accept")
                     .SetPreflightMaxAge(TimeSpan.FromMinutes(10));
                }
            });
        });

        services.AddRateLimiter(o =>
        {
            var limits = auth.RateLimits;
            o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            o.OnRejected = async (context, ct) =>
            {
                context.HttpContext.Response.Headers.RetryAfter = "10";
                context.HttpContext.Response.ContentType = "application/json";
                await context.HttpContext.Response.WriteAsync(
                    "{\"error\":\"temporarily_unavailable\",\"error_description\":\"Too many requests.\"}", ct).ConfigureAwait(false);
            };

            RateLimitPartition<string> TokenBucket(HttpContext http) => !limits.Enabled
                ? RateLimitPartition.GetNoLimiter("off")
                : RateLimitPartition.GetTokenBucketLimiter(ClientIp(http), _ => new TokenBucketRateLimiterOptions
                {
                    TokenLimit = Math.Max(1, limits.TokenBurst),
                    TokensPerPeriod = Math.Max(1, limits.TokenPerSecond),
                    ReplenishmentPeriod = TimeSpan.FromSeconds(1),
                    QueueLimit = 0,
                    AutoReplenishment = true,
                });

            o.AddPolicy("token", TokenBucket);
            o.AddPolicy("authorize", http => limits.Enabled && HttpMethods.IsPost(http.Request.Method)
                ? RateLimitPartition.GetFixedWindowLimiter("login:" + ClientIp(http), _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = Math.Max(1, limits.LoginPermitsPerWindow),
                    Window = TimeSpan.FromSeconds(Math.Max(1, limits.LoginWindowSeconds)),
                    QueueLimit = 0,
                    AutoReplenishment = true,
                })
                : TokenBucket(http));
        });
    }

    private static string ClientIp(HttpContext http) => http.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    public static void ConfigurePipeline(WebApplication app)
    {
        var auth = app.Services.GetRequiredService<IOptions<AuthServerOptions>>().Value;

        // Fail fast: keys and metadata are materialised before the first request.
        _ = app.Services.GetRequiredService<DiscoveryDocument>();
        if (!auth.RequireHttps && !app.Environment.IsDevelopment())
            Log.HttpsDisabled(app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("AddAccion.Auth"));

        app.UseForwardedHeaders();
        if (!string.IsNullOrEmpty(auth.Proxy.PathBase)) app.UsePathBase(auth.Proxy.PathBase);
        app.UseOAuthExceptionHandler();
        app.UseMiddleware<SecurityHeadersMiddleware>();
        if (auth.RequireHttps) app.UseMiddleware<RequireHttpsMiddleware>();
        app.UseRouting();
        app.UseCors();
        app.UseRateLimiter();

        app.MapGet(Routes.Discovery, Discovery).RequireCors("public");
        app.MapGet(Routes.OAuthMetadata, Discovery).RequireCors("public");
        app.MapGet(Routes.Jwks, (SigningKeyStore keys, HttpContext ctx) =>
        {
            ctx.Response.Headers.CacheControl = "public, max-age=900";
            return TypedResults.Bytes(keys.JwksJson, "application/json");
        }).RequireCors("public");

        app.MapGet(Routes.Authorize, (HttpContext ctx, AuthorizeEndpoint e) => e.GetAsync(ctx)).RequireRateLimiting("authorize");
        app.MapPost(Routes.Authorize, (HttpContext ctx, AuthorizeEndpoint e) => e.PostAsync(ctx)).RequireRateLimiting("authorize");
        app.MapPost(Routes.Token, (HttpContext ctx, TokenEndpoint e) => e.HandleAsync(ctx)).RequireRateLimiting("token").RequireCors("spa");
        app.MapPost(Routes.Introspect, (HttpContext ctx, TokenManagementEndpoints e) => e.IntrospectAsync(ctx)).RequireRateLimiting("token");
        app.MapPost(Routes.Revoke, (HttpContext ctx, TokenManagementEndpoints e) => e.RevokeAsync(ctx)).RequireRateLimiting("token").RequireCors("spa");
        app.MapMethods(Routes.UserInfo, ["GET", "POST"], (HttpContext ctx, UserInfoEndpoint e) => e.HandleAsync(ctx))
            .RequireRateLimiting("token").RequireCors("spa");

        AdminEndpoints.Map(app);

        app.MapHealthChecks(Routes.HealthLive, new HealthCheckOptions { Predicate = _ => false });
        app.MapHealthChecks(Routes.HealthReady, new HealthCheckOptions { Predicate = r => r.Tags.Contains("ready") });
    }

    private static FileContentHttpResult Discovery(DiscoveryDocument doc, HttpContext ctx)
    {
        ctx.Response.Headers.CacheControl = "public, max-age=3600";
        return TypedResults.Bytes(doc.Json, "application/json");
    }
}
