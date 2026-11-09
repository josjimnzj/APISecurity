using System.Net;
using AddAccion.Auth.Configuration;
using Microsoft.Extensions.Options;

namespace AddAccion.Auth.Hosting;

/// <summary>
/// Client IP used for rate limiting and audit logs: the edge header (e.g. CF-Connecting-IP) when configured and
/// well-formed, otherwise the connection address (already adjusted by trusted X-Forwarded-For).
/// </summary>
public static class ClientAddress
{
    public static string Resolve(HttpContext ctx)
    {
        var header = ctx.RequestServices.GetService<IOptions<AuthServerOptions>>()?.Value.Proxy.ClientIpHeader;
        return Resolve(ctx, header);
    }

    public static string Resolve(HttpContext ctx, string? header)
    {
        if (!string.IsNullOrWhiteSpace(header) && ctx.Request.Headers.TryGetValue(header, out var values) && values.Count == 1
            && values[0] is { Length: > 0 and <= 45 } candidate && IPAddress.TryParse(candidate, out var ip))
        {
            return ip.ToString();
        }
        return ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }
}
