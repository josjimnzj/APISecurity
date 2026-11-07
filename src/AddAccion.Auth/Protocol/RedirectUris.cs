using System.Net;

namespace AddAccion.Auth.Protocol;

/// <summary>Redirect URI rules: exact registration + exact match (OAuth 2.1 §2.3.1, RFC 9700 §4.1).</summary>
public static class RedirectUris
{
    /// <summary>
    /// Registration-time validation: absolute, no fragment, no wildcard, no userinfo, and either https,
    /// http on a loopback IP (native apps, RFC 8252 §7.3) or a private-use scheme with reverse-domain name (RFC 8252 §7.1).
    /// </summary>
    public static bool IsValidForRegistration(string uri, out string? reason)
    {
        reason = null;
        if (uri.Length > 2000) { reason = "too long"; return false; }
        if (uri.Contains('*', StringComparison.Ordinal)) { reason = "wildcards are not allowed"; return false; }
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var u)) { reason = "must be an absolute URI"; return false; }
        if (uri.Contains('#', StringComparison.Ordinal)) { reason = "must not contain a fragment"; return false; }
        if (!string.IsNullOrEmpty(u.UserInfo)) { reason = "must not contain user info"; return false; }

        if (u.Scheme == Uri.UriSchemeHttps) return true;
        if (u.Scheme == Uri.UriSchemeHttp)
        {
            if (IPAddress.TryParse(u.Host.Trim('[', ']'), out var ip) && IPAddress.IsLoopback(ip)) return true;
            reason = "http is only allowed for loopback IP addresses (127.0.0.1 / [::1])";
            return false;
        }
        if (u.Scheme.Contains('.', StringComparison.Ordinal) && u.Scheme is not ("javascript" or "data" or "file" or "vbscript"))
            return true;

        reason = "scheme must be https, loopback http or a reverse-domain private-use scheme";
        return false;
    }

    /// <summary>
    /// Runtime match: exact string comparison, except that the port of a loopback http redirect URI may vary (RFC 8252 §7.3).
    /// </summary>
    public static bool Matches(IReadOnlyList<string> registered, string requested)
    {
        foreach (var r in registered)
        {
            if (string.Equals(r, requested, StringComparison.Ordinal)) return true;
        }

        if (!Uri.TryCreate(requested, UriKind.Absolute, out var req) || req.Scheme != Uri.UriSchemeHttp
            || !IPAddress.TryParse(req.Host.Trim('[', ']'), out var ip) || !IPAddress.IsLoopback(ip))
        {
            return false;
        }

        foreach (var r in registered)
        {
            if (!Uri.TryCreate(r, UriKind.Absolute, out var reg) || reg.Scheme != Uri.UriSchemeHttp) continue;
            if (string.Equals(reg.Host, req.Host, StringComparison.OrdinalIgnoreCase)
                && string.Equals(reg.PathAndQuery, req.PathAndQuery, StringComparison.Ordinal)
                && reg.IsDefaultPort)
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>Origin (scheme://host[:port]) used for the CSP form-action directive, or null for custom schemes.</summary>
    public static string? HttpOrigin(string uri) =>
        Uri.TryCreate(uri, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttps || u.Scheme == Uri.UriSchemeHttp)
            ? u.GetLeftPart(UriPartial.Authority)
            : null;

    /// <summary>Appends query parameters, preserving an existing query component of the redirect URI.</summary>
    public static string AppendQuery(string redirectUri, IEnumerable<KeyValuePair<string, string?>> parameters)
    {
        var builder = new System.Text.StringBuilder(redirectUri);
        var hasQuery = redirectUri.Contains('?', StringComparison.Ordinal);
        foreach (var (key, value) in parameters)
        {
            if (value is null) continue;
            builder.Append(hasQuery ? '&' : '?');
            hasQuery = true;
            builder.Append(Uri.EscapeDataString(key)).Append('=').Append(Uri.EscapeDataString(value));
        }
        return builder.ToString();
    }
}
