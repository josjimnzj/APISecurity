using AddAccion.Auth.Configuration;
using AddAccion.Auth.Endpoints;
using AddAccion.Auth.Persistence;
using AddAccion.Auth.Protocol;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace AddAccion.Auth.Hosting;

/// <summary>Baseline response hardening (OWASP Secure Headers / ASVS V14.4).</summary>
public sealed class SecurityHeadersMiddleware(RequestDelegate next, IOptions<AuthServerOptions> options)
{
    private readonly bool _https = options.Value.RequireHttps;

    public Task InvokeAsync(HttpContext ctx)
    {
        ctx.Response.OnStarting(static state =>
        {
            var (c, https) = ((HttpContext, bool))state;
            var h = c.Response.Headers;
            h.XContentTypeOptions = "nosniff";
            h["Referrer-Policy"] = "no-referrer";
            h["Cross-Origin-Resource-Policy"] = "same-site";
            h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()";
            if (!h.ContainsKey("Content-Security-Policy"))
                h.ContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";
            if (!h.ContainsKey("X-Frame-Options")) h.XFrameOptions = "DENY";
            if (!h.ContainsKey("Cache-Control")) h.CacheControl = "no-store";
            if (https && c.Request.IsHttps) h.StrictTransportSecurity = "max-age=31536000; includeSubDomains";
            return Task.CompletedTask;
        }, (ctx, _https));
        return next(ctx);
    }
}

/// <summary>Rejects plain HTTP (after forwarded-header processing). Health probes stay reachable over HTTP inside the cluster.</summary>
public sealed class RequireHttpsMiddleware(RequestDelegate next)
{
    public Task InvokeAsync(HttpContext ctx)
    {
        if (ctx.Request.IsHttps || ctx.Request.Path.StartsWithSegments("/health", StringComparison.Ordinal))
            return next(ctx);

        ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
        ctx.Response.ContentType = "application/json";
        return ctx.Response.WriteAsync("{\"error\":\"invalid_request\",\"error_description\":\"HTTPS is required.\"}");
    }
}

public sealed class DatabaseHealthCheck(IDatabaseHealth database) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(3));
            return await database.PingAsync(cts.Token).ConfigureAwait(false)
                ? HealthCheckResult.Healthy()
                : HealthCheckResult.Unhealthy("database");
        }
#pragma warning disable CA1031 // health checks must not throw
        catch (Exception)
#pragma warning restore CA1031
        {
            // No exception details in the probe response.
            return HealthCheckResult.Unhealthy("database");
        }
    }
}

/// <summary>Periodic deletion of expired codes, refresh tokens, revocations and assertion jtis. Idempotent across replicas.</summary>
public sealed class CleanupService(IGrantStore grants, IOptions<AuthServerOptions> options, TimeProvider time, ILogger<CleanupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var o = options.Value.Cleanup;
        if (!o.Enabled) return;

        // Random initial delay spreads replicas and keeps cleanup off the startup path.
        var jitter = TimeSpan.FromSeconds(Random.Shared.Next(30, Math.Max(31, o.IntervalSeconds)));
        try
        {
            await Task.Delay(jitter, time, stoppingToken).ConfigureAwait(false);
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(Math.Max(60, o.IntervalSeconds)), time);
            do
            {
                try
                {
                    var removed = await grants.CleanupAsync(time.GetUtcNow(), o.BatchSize, stoppingToken).ConfigureAwait(false);
                    if (removed > 0) Log.CleanupCompleted(logger, removed);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    Log.CleanupFailed(logger, ex);
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // shutdown
        }
    }
}

internal static class ExceptionHandling
{
    /// <summary>Generic error body: no stack traces, exception types or SQL details leave the process (ASVS V7.4).</summary>
    public static void UseOAuthExceptionHandler(this IApplicationBuilder app)
    {
        app.UseExceptionHandler(handler => handler.Run(async ctx =>
        {
            var feature = ctx.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerPathFeature>();
            var logger = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("AddAccion.Auth.Errors");
            if (feature?.Error is { } error) Log.Unhandled(logger, error, feature.Path);

            ctx.Response.StatusCode = StatusCodes.Status500InternalServerError;
            OAuthResults.NoStore(ctx);
            await TypedResults.Json(new OAuthErrorResponse(OAuthErrors.ServerError, "An unexpected error occurred."),
                AuthJsonContext.Default.OAuthErrorResponse, statusCode: 500).ExecuteAsync(ctx).ConfigureAwait(false);
        }));
    }
}
