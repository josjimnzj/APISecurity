# Integración

## Cómo debe validar un token una API (resource server)

Validación local con JWKS — sin llamada por petición:

1. Descargar `https://auth.addaccion.com/.well-known/openid-configuration` → `jwks_uri`. Cachear JWKS; refrescar ante `kid` desconocido (con límite) y al menos cada 24 h.
2. Rechazar si: firma inválida, `alg` fuera de `RS256`/`ES256`, cabecera `typ` ≠ `at+jwt`, `iss` ≠ issuer, `aud` no contiene la audiencia de la API, `exp` vencido (tolerancia ≤ 60 s).
3. Autorizar con `scope` (separado por espacios) y, para usuarios, `roles`. `sub` = usuario (`client_id` igual a `sub` ⇒ token de sistema).

Claims del access token:

| Claim | Contenido |
|---|---|
| `iss`, `aud`, `exp`, `iat`, `jti` | Estándar |
| `sub` | Usuario (`UserId`) o, en `client_credentials`, el `client_id` |
| `client_id` | Cliente que obtuvo el token |
| `scope` | Scopes concedidos |
| `auth_time` | Momento del login (solo usuarios) |
| `roles` | Roles del usuario (si se pidió el scope `roles`) |

### .NET

```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o =>
{
    o.Authority = "https://auth.addaccion.com";
    o.Audience = "https://api.addaccion.com/erp";
    o.MapInboundClaims = false;
    o.TokenValidationParameters.ValidTypes = ["at+jwt"];
    o.TokenValidationParameters.ValidAlgorithms = ["ES256", "RS256"];
    o.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(30);
});
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("erp.read", p => p.RequireAssertion(c =>
        c.User.FindFirst("scope")?.Value.Split(' ').Contains("erp.read") == true));
```

### Go

```go
// github.com/MicahParks/keyfunc/v3 + github.com/golang-jwt/jwt/v5
k, _ := keyfunc.NewDefaultCtx(ctx, []string{"https://auth.addaccion.com/.well-known/jwks.json"})
tok, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
    if t.Header["typ"] != "at+jwt" { return nil, errors.New("not an access token") }
    return k.Keyfunc(t)
}, jwt.WithValidMethods([]string{"ES256", "RS256"}),
   jwt.WithIssuer("https://auth.addaccion.com"),
   jwt.WithAudience("https://api.addaccion.com/erp"),
   jwt.WithLeeway(30*time.Second))
```

### Introspección (revocación inmediata)

Para operaciones sensibles, o si la API no puede validar JWT, registrar la API como cliente confidencial con `can_introspect: true`:

```bash
curl -u 'erp-api:aasec_…' -d "token=$TOKEN" https://auth.addaccion.com/oauth2/introspect
# {"active":true,"scope":"erp.read","client_id":"erp-sync","sub":"…","aud":[…],"exp":…,"jti":"…"}
```

Cachear la respuesta positiva como mucho unos segundos; `active:false` no revela el motivo.

## Gateways (Azure API Management, Kong, NGINX, Envoy, Traefik)

Todos aceptan un proveedor OIDC por URL de discovery. Configurar: issuer/discovery URL, audiencia de la API, algoritmos `ES256,RS256`. Ejemplo APIM:

```xml
<validate-jwt header-name="Authorization" require-scheme="Bearer" failed-validation-httpcode="401">
  <openid-config url="https://auth.addaccion.com/.well-known/openid-configuration" />
  <audiences><audience>https://api.addaccion.com/erp</audience></audiences>
  <issuers><issuer>https://auth.addaccion.com</issuer></issuers>
  <required-claims><claim name="scope" match="any" separator=" "><value>erp.read</value></claim></required-claims>
</validate-jwt>
```

## Aplicaciones de AddACCION (usuarios)

- SPA / móvil / escritorio: cliente **público** (`client_type: public`), `authorization_code` + `refresh_token`, PKCE S256. Librerías certificadas: `oidc-client-ts` (SPA), AppAuth (iOS/Android), MSAL no aplica (es específico de Entra ID).
- Aplicación web con backend: cliente **confidencial** con `authorization_code` y secreto o `private_key_jwt`; tokens en el servidor (patrón BFF), nunca en `localStorage`.
- Scopes típicos: `openid profile email roles offline_access <api>.read`.
- Redirect URIs: https exacta; apps nativas `http://127.0.0.1/<ruta>` (cualquier puerto) o esquema propio `com.addaccion.app:/callback`.
- Logout: revocar el refresh token en `/oauth2/revoke` y borrar los tokens locales (sin sesión SSO en v1 no hay `end_session_endpoint`).

## Sistemas externos (partners)

| Nivel de confianza | Autenticación | Alta |
|---|---|---|
| Estándar | `client_secret_basic` (secreto de 256 bits, caduca en 365 días) | `create-client … --grants client_credentials --scopes …` |
| Alto (sin secreto compartido) | `private_key_jwt`: el partner genera su par de claves y entrega solo el JWKS público | `create-client … --auth private_key_jwt --jwks-file partner.jwks.json` |

Aserción `private_key_jwt` que debe generar el partner (firmada ES256/RS256/PS256):

```json
{ "iss": "<client_id>", "sub": "<client_id>", "aud": "https://auth.addaccion.com/oauth2/token",
  "jti": "<único>", "iat": 1794018950, "exp": 1794019070 }
```

```bash
curl -d grant_type=client_credentials \
     -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
     -d client_assertion=$JWT https://auth.addaccion.com/oauth2/token
```

`exp` como máximo 5 minutos en el futuro; cada `jti` se acepta una sola vez.

## Otros IAM

- **Como IdP para otro IAM** (Keycloak, Okta, Entra ID External ID, Ping): registrar AddACCION Auth como proveedor OIDC "genérico" con la URL de discovery, un cliente confidencial con `authorization_code` y la redirect URI del IAM, scopes `openid profile email`. El IAM recibe `id_token` con `sub`, `email`, `name`.
- **Federación entrante** (login con Entra ID/AD en lugar de contraseña local): no incluida en v1; ver hoja de ruta en [arquitectura](arquitectura.md#hoja-de-ruta).
- **SIEM**: eventos con `EventId` estable ([operación](operacion.md#monitorización)).
