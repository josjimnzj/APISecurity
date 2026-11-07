# Controles de seguridad

Mapeo de cada control a OWASP ASVS 4.0.3, OWASP API Security Top 10 (2023) y OAuth 2.0 Security BCP (RFC 9700). Los controles marcados con **[T]** tienen test automatizado en `tests/`.

## Protocolo OAuth / OIDC (RFC 9700, OAuth 2.1)

| Control | Implementación | Referencia |
|---|---|---|
| Sin implicit ni password grant | Solo `code`, `client_credentials`, `refresh_token`; `response_type=token` → `unsupported_response_type` **[T]** | RFC 9700 §2.1.2, §2.4 |
| PKCE obligatorio, solo S256 | Sin `code_challenge` o con `plain` → error **[T]**; verificador 43–128 chars | RFC 7636, OAuth 2.1 §4.1.1 |
| `redirect_uri` exacto | Comparación ordinal; sin comodines; prefijos y subdominios rechazados **[T]**; puerto variable solo para loopback (apps nativas) **[T]** | RFC 9700 §4.1.3, RFC 8252 §7.3 |
| Errores sin redirección cuando el cliente o la URI no son válidos | Página local 400 **[T]** | RFC 6749 §4.1.2.1 |
| Mix‑up | Parámetro `iss` en todas las respuestas de autorización **[T]** | RFC 9207 |
| Código de un solo uso, 60 s | UPDATE condicional atómico; reutilización revoca lo emitido **[T]**; expiración **[T]** | RFC 6749 §4.1.2 |
| Código ligado a cliente, redirect y PKCE | Validados en la misma sentencia SQL **[T]** | RFC 6749 §4.1.3 |
| Rotación de refresh tokens + detección de reutilización | Reutilización o presentación por otro cliente revoca la familia **[T]**; caducidad absoluta **[T]** | RFC 9700 §4.14.2 |
| No ampliar scope en refresh | **[T]** | RFC 6749 §6 |
| Parámetros duplicados rechazados | **[T]** | RFC 6749 §3.1 |
| Un único método de autenticación de cliente | **[T]** | RFC 6749 §2.3 |
| `private_key_jwt`: firma asimétrica, `aud`, vida máx. 5 min, `jti` único | Anti‑replay persistente **[T]**; aud ajena **[T]**; vida larga **[T]**; clave ajena **[T]**; caducada **[T]** | RFC 7523, OIDC Core §9 |
| JWKS de clientes sin claves simétricas ni privadas, RSA ≥ 2048 | **[T]** | RFC 7517 |
| Tokens de acceso tipados | `typ: at+jwt` exigido al validar (evita usar ID tokens como access tokens) | RFC 9068 §4 |
| Confusión de algoritmos / `alg: none` | Lista blanca de algoritmos por clave, `kid` obligatorio y coincidente **[T]** | RFC 8725 §3.1 |
| Respuestas de token no cacheables | `Cache-Control: no-store`, `Pragma: no-cache` **[T]** | RFC 6749 §5.1 |
| Introspección autenticada y autorizada | Solo clientes con `can_introspect` **[T]**; refresh tokens solo para su propio cliente | RFC 7662 §4 |
| Revocación sin oráculo | Siempre 200; solo el cliente propietario revoca **[T]** | RFC 7009 §2.2 |

## OWASP API Security Top 10 (2023)

| Riesgo | Mitigación |
|---|---|
| API1 Broken Object Level Authorization | Refresh tokens, revocación e introspección comprueban el cliente propietario **[T]** |
| API2 Broken Authentication | Ver tabla de protocolo y de credenciales |
| API3 Broken Object Property Level Authorization | DTOs explícitos en la API de administración; los hashes nunca se devuelven; el secreto solo en la respuesta de creación |
| API4 Unrestricted Resource Consumption | Rate limit por IP (token bucket en token/introspect/revoke/admin; ventana fija en login); cuerpo ≤ 64 KB, ≤ 64 campos de formulario, cabeceras ≤ 32 KB; tokens ≤ 8 KB antes de parsear; semáforo de PBKDF2; iteraciones PBKDF2 acotadas |
| API5 Broken Function Level Authorization | `/admin/v1` exige `aud=urn:addaccion:auth:admin` + scope `auth.admin` **[T]** |
| API6 Unrestricted Access to Sensitive Business Flows | Bloqueo de cuenta tras N fallos **[T]** + rate limit por IP |
| API7 SSRF | El servicio no hace peticiones salientes a URLs proporcionadas (JWKS de clientes almacenados, no remotos) |
| API8 Security Misconfiguration | Validación de configuración al arrancar (issuer https, claves, clave CSRF, CORS sin comodines) **[T]**; errores genéricos sin trazas; cabeceras de seguridad **[T]** |
| API9 Improper Inventory Management | Discovery como inventario de endpoints; versión en la ruta de administración |
| API10 Unsafe Consumption of APIs | Las vistas de usuarios se leen de forma tolerante y cerrada ante datos ambiguos (login duplicado = no encontrado) |

## OWASP ASVS (selección relevante)

| Capítulo | Requisito | Implementación |
|---|---|---|
| V2.1 Contraseñas | Longitud máxima ≥ 64 aceptada, sin truncar | Hasta 1024 caracteres |
| V2.2 Autenticación genérica | Mensaje único para usuario inexistente, contraseña errónea, cuenta bloqueada o inactiva **[T]**; mismo coste de CPU (hash ficticio) | `AuthorizeEndpoint.PostAsync` |
| V2.2.1 Anti‑automatización | Bloqueo (5 fallos / 15 min por defecto) + rate limit | `UserLoginState`, `AddRateLimiter` |
| V2.4 Almacenamiento de credenciales | Contraseñas PBKDF2 (Identity v3); v2 legado aceptado pero registrado como débil; secretos de cliente/códigos/refresh: SHA‑256 de 256 bits aleatorios | `IdentityPasswordHashVerifier`, `TokenHasher` |
| V2.9 Verificador criptográfico | Comparaciones en tiempo constante (`FixedTimeEquals`) | Secretos, CSRF, PBKDF2 |
| V3.4 Cookies | `__Host-` prefijo, `Secure`, `HttpOnly`, `SameSite=Lax` | Cookie CSRF del login |
| V4.2.2 CSRF | Doble envío **firmado** (HMAC, HKDF de clave compartida) + comprobación de `Origin`/`Sec-Fetch-Site` **[T]** | `CsrfProtector` |
| V5.3 Codificación de salida | HTML‑encoding de todo valor dinámico; JSON por serializador; parámetros de redirección escapados | `LoginPage`, `RedirectUris.AppendQuery` |
| V5.3.4 Inyección SQL | 100 % consultas parametrizadas con tipo y tamaño | `Persistence/SqlServer` |
| V6.2 Algoritmos | RSA ≥ 2048, EC P‑256/384/521, sin HMAC con claves públicas, CSPRNG para todos los valores aleatorios | `SigningKeyStore`, `RandomTokens` |
| V6.4 Gestión de secretos | Claves privadas fuera de la BD y de la imagen (secret montado); secretos de cliente mostrados una vez; prefijo `aasec_` para detección por escáneres | — |
| V7.1 Logs | Eventos de autenticación con quién/qué/resultado; nunca contraseñas, secretos, códigos ni tokens (solo `jti`); login desconocido como huella SHA‑256 truncada | `Hosting/Infrastructure.cs` (`Log`) |
| V7.4 Errores | Manejador global: `server_error` genérico, sin excepción ni SQL | `ExceptionHandling` |
| V9.1 TLS | `RequireHttps` (tras `X-Forwarded-Proto` de proxies de confianza), HSTS, issuer https obligatorio | `RequireHttpsMiddleware` |
| V13.1 API genérica | Solo `application/x-www-form-urlencoded` en endpoints OAuth **[T]**; métodos explícitos | `FormReader` |
| V14.2 Dependencias | NuGet audit en cada build (`NuGetAuditMode=all`), dependencias transitivas vulnerables fijadas a versión parcheada, Dependabot | `Directory.Packages.props` |
| V14.4 Cabeceras | `X-Content-Type-Options`, `X-Frame-Options: DENY`, CSP `default-src 'none'` (login: nonce por respuesta, `form-action` limitado a la app destino, `frame-ancestors 'none'`), `Referrer-Policy: no-referrer`, sin cabecera `Server` **[T]** | `SecurityHeadersMiddleware` |
| V14.5 Validación de cabeceras | Proxies de confianza explícitos; `Host` no usado para construir URLs | `ForwardedHeadersOptions`, `Auth:Issuer` |

## Contenedor

| Control | Implementación |
|---|---|
| Superficie mínima | Imagen chiseled: sin shell, sin gestor de paquetes |
| Mínimo privilegio | UID 1654 no root, `readOnlyRootFilesystem`, `capabilities: drop ALL`, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`, sin token de service account |
| BD | Rol `auth_service` con DML solo en `auth.*` y lectura de vistas (`db/examples/permissions.example.sql`); migraciones con identidad separada (`ConnectionStrings:AuthDbMigrations`) |

## Riesgos residuales conocidos

- Los JWT de acceso revocados siguen siendo válidos para APIs que validan **solo** localmente hasta su `exp` (10 min por defecto). Las APIs de alto riesgo deben introspectar o reducir la vida del token por cliente.
- El rate limit es por réplica. Con N réplicas el límite efectivo es N×; complementar en WAF/ingress.
- Sin MFA en v1. Cuentas privilegiadas deberían federarse con un IdP con MFA (hoja de ruta).
- El bloqueo por cuenta permite a un atacante bloquear a un usuario conocido (DoS dirigido). Compensado con bloqueo temporal (no permanente) y rate limit por IP.
