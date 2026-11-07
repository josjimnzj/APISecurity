# Arquitectura

## Visión general

```
                         ┌──────────────────────────────────────────────┐
  Sistemas externos ───► │  AddACCION Auth (N réplicas, sin estado)      │
  (client_credentials,   │  Kestrel · Minimal APIs · Native AOT          │
   private_key_jwt)      │                                              │
                         │  caché local: clientes (60 s), scopes (120 s) │
  Usuarios (navegador) ─►│  claves de firma en memoria (secret montado) │
  SPA / móvil (PKCE)     └───────────────┬──────────────────────────────┘
                                         │ ADO.NET (pool, TLS)
  APIs AddACCION ◄── JWKS (local)        ▼
  Gateways / IAM ◄── discovery   ┌──────────────────────────────┐
                    introspect   │ SQL Server                    │
                                 │  auth.*  (propiedad del svc)  │
                                 │  auth.vw_Users / vw_UserRoles │──► tablas de usuarios existentes (solo lectura)
                                 └──────────────────────────────┘
```

Toda la coordinación entre réplicas pasa por SQL Server (códigos, refresh tokens, revocaciones, anti‑replay, bloqueo de cuentas). No hay estado de sesión en memoria: cualquier réplica atiende cualquier petición, escalado horizontal sin afinidad.

## Decisiones

| Decisión | Alternativas descartadas | Motivo |
|---|---|---|
| Implementación propia acotada a un subconjunto de OAuth 2.1/OIDC | Duende IdentityServer (licencia comercial), OpenIddict (EF Core, sin AOT), Keycloak (JVM, otro stack, otro almacén de usuarios) | Arranque en ms, AOT, control total del modelo de datos sobre las tablas existentes, mismo contrato portable a Go. Se mitiga el riesgo de protocolo con una suite de conformidad HTTP y librería estándar de JWT (Microsoft.IdentityModel) |
| .NET 10 Native AOT + `CreateSlimBuilder` | JIT + ReadyToRun | ~90 ms al primer request y ~47 MB RSS: elimina el problema de cold start que motivaba Go |
| ADO.NET puro (Microsoft.Data.SqlClient) | EF Core, Dapper | Compatible AOT, cero reflexión, SQL explícito y portable a Go literalmente, parámetros tipados con tamaño (planes estables) |
| JWT de acceso autocontenidos (RFC 9068) | Tokens opacos | Las APIs validan sin red; la revocación inmediata está disponible vía introspección. Vida corta (10 min por defecto) |
| Refresh tokens opacos con rotación | Refresh JWT | Revocables, almacenados solo como SHA‑256, detección de robo por reutilización |
| SHA‑256 para secretos de cliente, códigos y refresh tokens | PBKDF2/Argon2 | Son valores aleatorios de 256 bits generados por el servidor: una KDF lenta no añade seguridad y haría el endpoint de token CPU‑bound |
| PBKDF2 (formato ASP.NET Identity) para contraseñas de usuario | — | Compatibilidad con hashes existentes; verificador intercambiable (`IPasswordHashVerifier`) |
| Claves de firma en ficheros PEM montados (secret) | Claves en BD, generación automática | La clave privada no pasa por la BD; rotación declarativa; `kid` = huella RFC 7638 (determinista entre lenguajes) |
| Usuarios a través de vistas contrato | Leer tablas directamente | Desacopla el servicio del esquema existente; el DBA adapta la vista, no el código |
| Login server‑side sin JavaScript | Login embebido en cada app | OAuth 2.1 exige que la contraseña solo se introduzca en el AS; CSP estricta posible |

## Flujos

### Sistema externo (`client_credentials`)

```
Sistema ── POST /oauth2/token (Basic o client_assertion) ──► Auth
                                                         1. cliente desde caché (BD solo en miss)
                                                         2. SHA-256 + comparación en tiempo constante
                                                            (o validación de aserción + jti en BD)
                                                         3. scopes ⊆ permitidos → aud = audiencias de los scopes
                                                         4. firma JWT
Sistema ◄────────────── access_token (JWT, 10 min) ──────
```
Camino caliente sin BD con `client_secret_*`; con `private_key_jwt` hay un INSERT (anti‑replay del `jti`).

### Usuario (`authorization_code` + PKCE)

```
App ── 302 → /oauth2/authorize?client_id&redirect_uri&scope&state&nonce&code_challenge(S256)
Auth: valida cliente + redirect_uri exacto (si falla: página de error, NUNCA redirige)
      → formulario de login (cookie CSRF firmada + token en el formulario, CSP con nonce)
Usuario ── POST credenciales
Auth: origen + CSRF → revalida todos los parámetros → usuario por LoginName (1 query con estado de bloqueo)
      → PBKDF2 (concurrencia limitada) → código (256 bits, 60 s, se guarda su hash)
      ── 303 → redirect_uri?code&state&iss
App ── POST /oauth2/token (code, code_verifier, redirect_uri)
Auth: UPDATE condicional atómico (hash, cliente, redirect, S256(verifier), no caducado, no consumido)
      → usuario activo + roles → access_token + id_token + refresh_token
      si el código ya estaba consumido: revoca el refresh y el access emitidos con él
```

### Refresh

Cada uso consume el token y emite otro de la misma familia en una transacción. Presentar un token ya consumido (o por otro cliente) revoca la familia completa. La caducidad absoluta de la familia no se extiende con la rotación. El usuario se vuelve a comprobar (activo, roles actuales) en cada refresh.

## Modelo de datos (`auth.*`)

| Tabla | Contenido | Volumen / limpieza |
|---|---|---|
| `Clients`, `ClientSecrets`, `ClientRedirectUris`, `ClientScopes` | Registro de clientes; secretos como `binary(32)` SHA‑256, varios activos para rotación | Bajo |
| `Scopes` | Scope → audiencia (`aud`) | Bajo |
| `AuthorizationCodes` | Hash, PKCE challenge, vínculo a lo emitido (familia, jti) | 1 fila por login; borrado 1 día tras expirar |
| `RefreshTokens` | Hash, familia, estado consumido/revocado | 1 fila por refresh; borrado al expirar la familia |
| `RevokedAccessTokens` | `jti` revocados hasta su `exp` | Bajo |
| `ClientAssertionJtis` | Anti‑replay `private_key_jwt` | 1 fila por token M2M con clave privada; borrado al expirar |
| `UserLoginState` | Fallos y bloqueo, separado de las tablas de usuarios | 1 fila por usuario con fallos |

Identificadores, hashes y URIs con collation `Latin1_General_100_BIN2` (comparación exacta exigida por OAuth). Claves primarias `bigint IDENTITY` + índice único sobre el hash (sin fragmentación por claves aleatorias). La limpieza (`CleanupService`) borra en lotes de 5.000 cada 15 min con jitter; es idempotente entre réplicas.

## Rendimiento

- Caché de clientes y scopes en memoria con límite de tamaño; caché negativa corta para IDs inexistentes.
- Discovery y JWKS pre‑serializados en arranque.
- JSON con source generators (`AuthJsonContext`), logging con `LoggerMessage` generado.
- Una sola ida a BD para canjear un código (UPDATE … OUTPUT + diagnóstico en el mismo batch) y para rotar refresh (transacción en el mismo batch).
- PBKDF2 limitado por semáforo (por defecto = nº de CPUs) para que un ataque al login no consuma la CPU del endpoint de token.
- El coste dominante es la firma: **ES256 es ~6× más rápido que RSA‑3072**. Recomendación: clave activa EC P‑256; mantener RSA publicada si algún sistema solo admite RS256.

## Despliegue

- Imagen `runtime-deps:10.0-noble-chiseled-extra`: sin shell ni gestor de paquetes, usuario no root, rootfs de solo lectura (no escribe en disco).
- Probes: `startup`/`liveness` → `/health/live`; `readiness` → `/health/ready` (BD y vistas de usuarios).
- TLS terminado en el ingress; `Auth:Proxy:KnownNetworks` debe contener la red del ingress para confiar en `X-Forwarded-Proto/For`. El emisor (`Auth:Issuer`) es configuración, nunca se deriva de la cabecera `Host`.

## Hoja de ruta

| Prioridad | Funcionalidad | Nota |
|---|---|---|
| Alta | Sesión SSO (cookie) + `end_session_endpoint` | Evita re‑login entre apps; requiere tabla de sesiones |
| Alta | Federación entrante con Entra ID / AD (OIDC upstream) | Usuarios corporativos sin contraseña local |
| Alta | MFA (TOTP / WebAuthn) para el login | ASVS nivel 2 para cuentas privilegiadas |
| Media | `jwks_uri` remoto para `private_key_jwt` | Rotación de claves del partner sin intervención |
| Media | mTLS (RFC 8705) o DPoP (RFC 9449) | Tokens ligados a remitente para partners críticos |
| Media | Token Exchange (RFC 8693) | Delegación servicio → servicio |
| Media | Device Authorization Grant (RFC 8628) | CLIs / dispositivos sin navegador |
| Baja | Pantalla de consentimiento para clientes de terceros | Hoy todos los clientes son de confianza (registrados por AddACCION) |
| Baja | Límite de tasa distribuido (Redis) | Hoy por réplica; complementar con WAF/gateway |
