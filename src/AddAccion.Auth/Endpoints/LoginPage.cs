using System.Text;
using System.Text.Encodings.Web;
using System.Text.Unicode;
using AddAccion.Auth.Crypto;

namespace AddAccion.Auth.Endpoints;

/// <summary>
/// Server-rendered login and error pages. No JavaScript; every dynamic value is HTML-encoded;
/// strict per-response CSP with a style nonce; cannot be framed (clickjacking).
/// </summary>
internal static class LoginPage
{
    public const string InvalidCredentials = "Usuario o contraseña incorrectos.";

    /// <summary>Authorization request parameters carried through the form (re-validated on POST).</summary>
    public static readonly string[] ForwardedParameters =
        ["response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method", "nonce", "response_mode", "prompt"];

    public sealed record Model(
        string Brand,
        string ClientName,
        IReadOnlyList<KeyValuePair<string, string>> Hidden,
        string? LoginName,
        string? ErrorMessage,
        string? FormActionTarget);

    // Escapes HTML-significant characters only; Spanish letters stay readable.
    private static readonly HtmlEncoder Html = HtmlEncoder.Create(UnicodeRanges.All);

    private const string Css = """
        :root{color-scheme:light dark;--bg:#f4f6f8;--card:#fff;--fg:#1d2733;--muted:#5b6876;--accent:#0b5cad;--err:#b3261e;--line:#d5dbe1}
        @media (prefers-color-scheme:dark){:root{--bg:#11161c;--card:#1a222b;--fg:#e6ebf0;--muted:#9aa7b4;--accent:#5aa2ef;--err:#f2b8b5;--line:#2c3742}}
        *{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:16px}
        main{width:100%;max-width:400px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:32px}
        h1{font-size:1.4rem;margin:0 0 4px}p.sub{margin:0 0 24px;color:var(--muted);font-size:.95rem}
        label{display:block;font-weight:600;margin:16px 0 6px}input[type=text],input[type=password]{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:8px;font:inherit;background:transparent;color:inherit}
        input:focus{outline:2px solid var(--accent);outline-offset:1px}button{margin-top:24px;width:100%;padding:11px;border:0;border-radius:8px;background:var(--accent);color:#fff;font:inherit;font-weight:600;cursor:pointer}
        .err{margin:0 0 8px;padding:10px 12px;border-radius:8px;border:1px solid var(--err);color:var(--err)}footer{margin-top:24px;color:var(--muted);font-size:.8rem}
        """;

    public static IResult Form(Model m, int status)
    {
        var sb = new StringBuilder(4096);
        sb.Append("<main><h1>").Append(Html.Encode(m.Brand)).Append("</h1>");
        sb.Append("<p class=\"sub\">Inicie sesión para continuar en <strong>").Append(Html.Encode(m.ClientName)).Append("</strong></p>");
        if (m.ErrorMessage is not null)
            sb.Append("<p class=\"err\" role=\"alert\">").Append(Html.Encode(m.ErrorMessage)).Append("</p>");
        sb.Append("<form method=\"post\" action=\"authorize\" autocomplete=\"on\" novalidate>");
        foreach (var (name, value) in m.Hidden)
        {
            sb.Append("<input type=\"hidden\" name=\"").Append(Html.Encode(name)).Append("\" value=\"").Append(Html.Encode(value)).Append("\">");
        }
        sb.Append("<label for=\"username\">Usuario</label>");
        sb.Append("<input type=\"text\" id=\"username\" name=\"username\" autocomplete=\"username\" autocapitalize=\"none\" spellcheck=\"false\" maxlength=\"256\" required autofocus value=\"")
          .Append(Html.Encode(m.LoginName ?? "")).Append("\">");
        sb.Append("<label for=\"password\">Contraseña</label>");
        sb.Append("<input type=\"password\" id=\"password\" name=\"password\" autocomplete=\"current-password\" maxlength=\"1024\" required>");
        sb.Append("<button type=\"submit\">Iniciar sesión</button></form>");
        sb.Append("<footer>Nunca le pediremos su contraseña fuera de esta página.</footer></main>");
        return new HtmlPageResult("Iniciar sesión", sb.ToString(), status, m.FormActionTarget);
    }

    public static IResult Error(string message, int status)
    {
        var body = "<main><h1>No se puede continuar</h1><p class=\"err\" role=\"alert\">" + Html.Encode(message) +
                   "</p><p class=\"sub\">Vuelva a la aplicación e inténtelo de nuevo. Si el problema persiste, contacte con soporte.</p></main>";
        return new HtmlPageResult("Error", body, status, formActionTarget: null);
    }

    private sealed class HtmlPageResult(string title, string body, int status, string? formActionTarget) : IResult
    {
        public Task ExecuteAsync(HttpContext ctx)
        {
            var nonce = RandomTokens.Create(16);
            var formAction = "form-action 'self'" + (formActionTarget is null ? "" : " " + formActionTarget);
            var headers = ctx.Response.Headers;
            headers.ContentSecurityPolicy =
                $"default-src 'none'; style-src 'nonce-{nonce}'; img-src 'self' data:; {formAction}; frame-ancestors 'none'; base-uri 'none'";
            headers.CacheControl = "no-store";
            headers.Pragma = "no-cache";
            headers.XFrameOptions = "DENY";
            ctx.Response.StatusCode = status;
            ctx.Response.ContentType = "text/html; charset=utf-8";

            var html = "<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
                       "<meta name=\"referrer\" content=\"no-referrer\"><meta name=\"robots\" content=\"noindex,nofollow\"><title>" + Html.Encode(title) +
                       "</title><style nonce=\"" + nonce + "\">" + Css + "</style></head><body>" + body + "</body></html>";
            return ctx.Response.WriteAsync(html, Encoding.UTF8, ctx.RequestAborted);
        }
    }
}
