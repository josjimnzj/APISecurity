using System.Text.Json.Serialization.Metadata;
using AddAccion.Auth.Hosting;
using AddAccion.Auth.Protocol;
using Microsoft.Net.Http.Headers;

namespace AddAccion.Auth.Endpoints;

internal static class OAuthResults
{
    /// <summary>RFC 6749 §5.1: token responses (and anything carrying credentials) must not be cached.</summary>
    public static void NoStore(HttpContext ctx)
    {
        ctx.Response.Headers.CacheControl = "no-store";
        ctx.Response.Headers.Pragma = "no-cache";
    }

    public static IResult Json<T>(HttpContext ctx, T value, JsonTypeInfo<T> typeInfo, int status = StatusCodes.Status200OK)
    {
        NoStore(ctx);
        return TypedResults.Json(value, typeInfo, statusCode: status);
    }

    public static IResult Error(HttpContext ctx, string error, string? description = null, int? status = null)
    {
        var code = status ?? error switch
        {
            OAuthErrors.InvalidClient => StatusCodes.Status401Unauthorized,
            OAuthErrors.ServerError => StatusCodes.Status500InternalServerError,
            OAuthErrors.TemporarilyUnavailable => StatusCodes.Status503ServiceUnavailable,
            _ => StatusCodes.Status400BadRequest,
        };
        return Json(ctx, new OAuthErrorResponse(error, description), AuthJsonContext.Default.OAuthErrorResponse, code);
    }

    /// <summary>RFC 6750 §3 error for protected resources (userinfo, admin API).</summary>
    public static IResult BearerError(HttpContext ctx, string error, string description, int status)
    {
        ctx.Response.Headers.WWWAuthenticate = $"Bearer error=\"{error}\", error_description=\"{description}\"";
        return Error(ctx, error, description, status);
    }
}

internal static class FormReader
{
    /// <summary>OAuth endpoints only accept application/x-www-form-urlencoded (RFC 6749 §3.2).</summary>
    public static async Task<(RequestParameters? Parameters, string? Error)> ReadAsync(HttpContext ctx)
    {
        if (!MediaTypeHeaderValue.TryParse(ctx.Request.ContentType, out var mediaType)
            || !mediaType.MediaType.Equals("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            return (null, "Content-Type must be application/x-www-form-urlencoded.");
        }

        IFormCollection form;
        try
        {
            form = await ctx.Request.ReadFormAsync(ctx.RequestAborted).ConfigureAwait(false);
        }
        catch (InvalidDataException)
        {
            return (null, "Request body exceeds the allowed limits.");
        }
        catch (BadHttpRequestException)
        {
            return (null, "Malformed request body.");
        }

        var parameters = RequestParameters.FromForm(form);
        return parameters.DuplicateParameter is { } dup
            ? (null, $"Parameter '{dup}' must not be repeated.")
            : (parameters, null);
    }

    public static string? BearerToken(HttpContext ctx)
    {
        var header = ctx.Request.Headers.Authorization;
        if (header.Count != 1 || header[0] is not { } value) return null;
        return value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? value[7..].Trim() : null;
    }
}
