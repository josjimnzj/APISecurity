# Operación

## Configuración

Todo se configura con variables de entorno (`__` como separador) o `appsettings.json`. El arranque falla si la configuración es insegura o incompleta.

| Clave | Por defecto | Descripción |
|---|---|---|
| `ConnectionStrings__AuthDb` | — | Conexión de la aplicación (rol `auth_service`). Usar `Encrypt=True`. |
| `ConnectionStrings__AuthDbMigrations` | = AuthDb | Conexión con permisos DDL solo para `migrate` |
| `Auth__Issuer` | — | URL pública exacta, https, sin `/` final. Aparece en `iss` de todos los tokens: **no cambiar** una vez en producción |
| `Auth__RequireHttps` | `true` | Rechaza HTTP (tras `X-Forwarded-Proto`). Health exento |
| `Auth__SigningKeys__Path` | — | Directorio con `*.pem` |
| `Auth__SigningKeys__ActiveKey` | único fichero | Nombre del fichero que firma |
| `Auth__Login__CsrfKey` | — | Base64 de ≥ 32 bytes, igual en todas las réplicas (`openssl rand -base64 32`) |
| `Auth__Login__MaxFailedAttempts` / `LockoutSeconds` | 5 / 900 | Bloqueo de cuenta |
| `Auth__Login__MaxConcurrentPasswordVerifications` | nº CPUs | Límite de PBKDF2 concurrentes |
| `Auth__Tokens__AuthorizationCodeLifetimeSeconds` | 60 | |
| `Auth__Tokens__IdTokenLifetimeSeconds` | 300 | |
| `Auth__Tokens__ClientAssertionMaxLifetimeSeconds` | 300 | Vida máxima aceptada de aserciones `private_key_jwt` |
| `Auth__Tokens__ClockSkewSeconds` | 30 | |
| `Auth__Caching__ClientCacheSeconds` | 60 | Propagación máxima de cambios de cliente a otras réplicas |
| `Auth__RateLimits__*` | 100 ráfaga / 50 por s; login 10/min | Por IP y réplica |
| `Auth__Cors__AllowedOrigins__N` | — | Orígenes exactos de SPAs |
| `Auth__Proxy__KnownNetworks__N` / `KnownProxies__N` | — | Proxies cuyo `X-Forwarded-*` se acepta |
| `Auth__Proxy__PathBase` | — | Si el issuer tiene ruta (`https://api.addaccion.com/auth` → `/auth`) |
| `Auth__Users__UseVarcharParameters` | `false` | Ver [usuarios](usuarios-sql-server.md) |
| `Auth__Cleanup__IntervalSeconds` | 900 | Limpieza de filas caducadas |

La vida de access/refresh token es **por cliente** (`access_token_lifetime` 60–86400 s, `refresh_token_lifetime` 300 s–1 año).

## Claves de firma

Generación: `AddAccion.Auth generate-key --type ec --out ec-2026-11.pem` (o `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`). Guardar en el gestor de secretos (Key Vault, Vault) y montarlas como secret de solo lectura. El `kid` publicado es la huella RFC 7638 de la clave pública.

Elección de algoritmo:
- **ES256 (EC P‑256)**: recomendado como clave activa; ~6× más throughput que RSA‑3072.
- **RS256 (RSA)**: mantener una publicada si algún RP/IAM solo acepta RS256 (requisito estricto de OIDC Discovery). Hacerla activa si un consumidor no soporta ES256.

Rotación sin corte (cada 6–12 meses, o inmediata si hay compromiso):

1. Añadir la nueva clave al secret **sin** cambiar `ActiveKey`. Desplegar. Ya aparece en JWKS.
2. Esperar a que los consumidores refresquen JWKS (las librerías lo hacen a las 24 h como máximo, y al ver un `kid` desconocido). 24 h es un margen seguro.
3. Cambiar `ActiveKey` a la nueva. Desplegar.
4. Tras la vida máxima de los access tokens emitidos con la anterior (≤ 24 h), retirar la clave antigua del secret. Desplegar.

Compromiso de clave: retirar la clave comprometida inmediatamente (pasos 1+3+4 a la vez). Todos los tokens firmados con ella dejan de validar; los clientes obtienen tokens nuevos con su refresh token o credenciales.

## Secretos de cliente

- Se generan en el servidor (256 bits, prefijo `aasec_`), se muestran una vez y se almacenan como SHA‑256.
- Rotación: `POST /admin/v1/clients/{id}/secrets` → el cliente cambia al nuevo → `DELETE /admin/v1/clients/{id}/secrets/{secretId}` del antiguo. Ambos son válidos mientras coexisten.
- Caducidad por defecto 365 días (`secret_lifetime_days`).
- Baja inmediata de un sistema: `POST /admin/v1/clients/{id}/disable` (efectivo en ≤ `ClientCacheSeconds` en todas las réplicas).

## Despliegue

- Imagen: `docker build -t registry/addaccion/auth:<versión> .` (multi‑arch con `docker buildx --platform linux/amd64,linux/arm64`).
- Migraciones: ejecutar `migrate` como Job/initContainer **antes** del despliegue, con `AuthDbMigrations`. Son idempotentes.
- Kubernetes: [`deploy/kubernetes/addaccion-auth.yaml`](../deploy/kubernetes/addaccion-auth.yaml) (≥ 2 réplicas, PDB, HPA por CPU, probes, contexto de seguridad restringido).
- Recursos de referencia por réplica: 100m CPU / 64 Mi de request, 256 Mi de límite de memoria. La CPU escala con la tasa de firmas y de logins (PBKDF2).

## Monitorización

Logs JSON a stdout (fuera de Development). Eventos de seguridad con `EventId` estable para reglas SIEM:

| EventId | Nivel | Evento | Alertar si |
|---|---|---|---|
| 1001 | Info | Token emitido (grant, client, sub, jti) | — (auditoría) |
| 1002 | Warn | Fallo de autenticación de cliente | picos por cliente/IP |
| 1003 | Warn | Reutilización de código de autorización | cualquier ocurrencia |
| 1004 | Warn | Familia de refresh revocada (reuse / otro cliente) | cualquier ocurrencia |
| 2002 / 2003 | Warn | Login fallido (usuario conocido / desconocido) | picos (fuerza bruta, credential stuffing) |
| 2004 | Warn | Hash de contraseña débil | inventario |
| 3001 | Info | Acción de administración | toda acción (auditoría) |
| 5001 | Error | Excepción no controlada | cualquier ocurrencia |

Métricas (`System.Diagnostics.Metrics`, meter `AddAccion.Auth`): `auth.tokens.issued{grant_type}`, `auth.tokens.errors{grant_type,error}`, `auth.logins{result,reason}`, `auth.authorize.errors{error}`, `auth.security.events{kind}`, `auth.introspections`. Inspección rápida: `dotnet-counters monitor --counters AddAccion.Auth`; exportación con OpenTelemetry (añadir el exporter OTLP es el siguiente paso si la plataforma lo requiere).

Volumen de log: un evento por token emitido reduce el throughput ~30 % (medido). Si el volumen M2M es alto, subir `Logging__LogLevel__AddAccion.Auth.Endpoints.TokenEndpoint` a `Warning` y apoyarse en las métricas.
