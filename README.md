# AddACCION Auth — servidor OAuth 2.1 / OpenID Connect

Servicio central de emisión y validación de tokens para **sistemas externos** (máquina a máquina) y **usuarios de AddACCION** (navegador, SPA, móvil). Implementa OAuth 2.1 y OpenID Connect con los controles de OWASP ASVS / OAuth Security BCP (RFC 9700), lee los usuarios de **SQL Server** sin modificar sus tablas y se compila con **.NET 10 Native AOT** para contenedores de arranque rápido y bajo consumo.

| Medido en este repositorio (4 vCPU compartidas con el generador de carga) | Valor |
|---|---|
| Arranque de proceso hasta primera respuesta (AOT) | ~90 ms |
| `docker run` → `/health/ready` (con comprobación de BD) | ~400 ms |
| Memoria en reposo / bajo carga | ~17–47 MiB / ~55–62 MiB |
| `client_credentials` con ES256 | ~18.900 req/s, p50 1,5 ms, p99 4,7 ms |
| `client_credentials` con ES256 + log de auditoría por token | ~13.200 req/s |
| `client_credentials` con RSA‑3072 (RS256) | ~3.100 req/s |
| Tamaño del binario / imagen | 25 MB / ~115 MB (chiseled + ICU) |

## Qué cubre

| Necesidad | Mecanismo | Estándar |
|---|---|---|
| Sistemas externos obtienen token | `client_credentials` con `client_secret_basic`, `client_secret_post` o **`private_key_jwt`** (sin secreto compartido) | RFC 6749 §4.4, RFC 7523 |
| Usuarios de AddACCION inician sesión | `authorization_code` + **PKCE S256 obligatorio**, página de login propia | RFC 6749 §4.1, RFC 7636, OAuth 2.1 |
| Sesiones largas sin re‑login | `refresh_token` **rotado en cada uso** con detección de reutilización (revoca la familia) | RFC 9700 §4.14 |
| APIs validan tokens localmente | JWT de acceso perfil RFC 9068 (`typ: at+jwt`) firmados RS256/ES256, claves en JWKS | RFC 9068, RFC 7517 |
| APIs validan con revocación inmediata | Introspección | RFC 7662 |
| Logout / baja de un sistema | Revocación de refresh y access tokens | RFC 7009 |
| Identidad del usuario | ID Token + UserInfo | OIDC Core |
| Integración con otros IAM / gateways | Discovery (`openid-configuration`, `oauth-authorization-server`), JWKS, parámetro `iss` en la respuesta | OIDC Discovery, RFC 8414, RFC 9207 |
| Alta de sistemas externos | API de administración protegida por `auth.admin` + CLI | RFC 7591 (modelo de metadatos) |

Fuera de alcance en v1 (ver [docs/arquitectura.md](docs/arquitectura.md#hoja-de-ruta)): sesión SSO, consentimiento, federación entrante (Entra ID/AD), mTLS/DPoP, device flow, token exchange.

## Endpoints

| Método | Ruta | Uso |
|---|---|---|
| GET | `/.well-known/openid-configuration` · `/.well-known/oauth-authorization-server` | Metadatos (cacheables 1 h) |
| GET | `/.well-known/jwks.json` | Claves públicas de firma |
| GET/POST | `/oauth2/authorize` | Inicio del flujo de usuario / envío del formulario de login |
| POST | `/oauth2/token` | Emisión de tokens |
| POST | `/oauth2/introspect` | Validación online (solo clientes con `can_introspect`) |
| POST | `/oauth2/revoke` | Revocación |
| GET/POST | `/oauth2/userinfo` | Datos del usuario (`openid`) |
| POST/GET/DELETE | `/admin/v1/clients…` | Gestión de clientes (scope `auth.admin`) |
| GET | `/health/live` · `/health/ready` | Probes (ready comprueba BD y vistas de usuarios) |

## Puesta en marcha local

Requisitos: Docker, `openssl`.

```bash
./deploy/dev-setup.sh                                   # claves de firma + deploy/.env con secretos aleatorios
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up --build
curl http://localhost:8080/.well-known/openid-configuration
```

Sin Docker (SDK .NET 10 + SQL Server accesible):

```bash
export ConnectionStrings__AuthDb='Server=localhost,1433;Database=AddAccionAuthDev;User ID=sa;Password=...;Encrypt=True;TrustServerCertificate=True'
dotnet run --project src/AddAccion.Auth -- migrate
ASPNETCORE_ENVIRONMENT=Development dotnet run --project src/AddAccion.Auth -- --urls http://localhost:5080   # clave de firma efímera
```

## Alta de un sistema externo y primer token

```bash
# 1. Registrar el recurso (API) y su audiencia
AddAccion.Auth add-scope --name erp.read --audience https://api.addaccion.com/erp --description "ERP lectura"

# 2. Registrar el sistema externo (el secreto se muestra una sola vez; se guarda solo su SHA-256)
AddAccion.Auth create-client --id erp-sync --name "Sincronización ERP" --grants client_credentials --scopes erp.read

# 3. Pedir token
curl -u 'erp-sync:aasec_…' -d grant_type=client_credentials -d scope=erp.read https://auth.addaccion.com/oauth2/token
```

Para partners con requisitos altos usar `--auth private_key_jwt --jwks-file partner-jwks.json`: el partner firma una aserción con su clave privada y AddACCION solo guarda la clave pública.

Cliente administrador inicial (para usar la API `/admin/v1`):

```bash
AddAccion.Auth create-client --id auth-admin --name "Administración" --grants client_credentials --scopes auth.admin
```

## Validación del token en las APIs de AddACCION

Validación local (recomendada, sin llamada de red por petición):

```csharp
builder.Services.AddAuthentication().AddJwtBearer(o =>
{
    o.Authority = "https://auth.addaccion.com";            // descarga discovery + JWKS y los cachea
    o.Audience = "https://api.addaccion.com/erp";
    o.TokenValidationParameters.ValidTypes = ["at+jwt"];
    o.MapInboundClaims = false;
});
```

Si la API necesita enterarse de revocaciones antes de que caduque el token (10 min por defecto), usar `/oauth2/introspect`. Ejemplos para Go y gateways en [docs/integracion.md](docs/integracion.md).

## CLI incluida en el binario/imagen

| Comando | Descripción |
|---|---|
| `migrate` | Aplica `db/migrations` (usa `ConnectionStrings:AuthDbMigrations` si existe: identidad con permisos DDL separada) |
| `generate-key --type ec\|rsa --out f.pem` | Genera clave de firma PKCS#8 (permisos 0600) |
| `add-scope --name --audience [--description]` | Alta/actualización de scope de API |
| `create-client …` | Alta de cliente con las mismas validaciones que la API de administración |

## Estructura

```
src/AddAccion.Auth/      servicio (.NET 10, Minimal APIs, Native AOT)
  Endpoints/             authorize, token, introspect/revoke, userinfo, discovery, admin, página de login
  Protocol/              emisión/validación JWT, scopes, redirect URIs
  Security/              autenticación de clientes (secret, private_key_jwt)
  Crypto/                claves de firma, PKCE, hash de contraseñas, CSRF
  Persistence/SqlServer/ ADO.NET puro (SqlClient), parámetros tipados, 1 round-trip por operación crítica
db/migrations/           esquema auth.* (idempotente)
db/examples/             contrato de vistas de usuarios + permisos mínimos
tests/                   unitarios + suite HTTP de caja negra (memoria / SQL Server / binario externo)
deploy/                  docker-compose, Kubernetes
docs/                    arquitectura, OWASP, usuarios SQL Server, operación, integración, migración a Go
```

## Tests

```bash
dotnet test                                              # unitarios + flujo completo en memoria
AUTH_TEST_SQL='Server=localhost,1433;User ID=sa;Password=…;Encrypt=True;TrustServerCertificate=True' dotnet test   # + SQL Server real (BD temporal)
AUTH_TEST_BASE_URL=http://127.0.0.1:5199 AUTH_TEST_EXTERNAL_DB='…' dotnet test --filter ExternalProtocolTests     # contra un proceso externo (binario AOT, imagen, futura versión Go)
```

La suite de protocolo solo usa HTTP: es el contrato de conformidad que cualquier reimplementación (p. ej. Go) debe pasar. CI la ejecuta contra el binario Native AOT.

## Documentación

- [Arquitectura y decisiones](docs/arquitectura.md)
- [Controles OWASP / OAuth BCP](docs/seguridad-owasp.md)
- [Usuarios en SQL Server: contrato de vistas](docs/usuarios-sql-server.md)
- [Operación: claves, secretos, despliegue, monitorización](docs/operacion.md)
- [Integración con APIs, gateways e IAM](docs/integracion.md)
- [Migración a Go: análisis y contrato](docs/migracion-go.md)
