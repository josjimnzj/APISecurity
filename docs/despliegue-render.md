# Despliegue en Render

Render construye la imagen con el `Dockerfile` del repositorio (Native AOT), inyecta `PORT` (10000) y termina TLS en su balanceador. El servicio ya está preparado para eso: escucha en `0.0.0.0:$PORT`, confía en `X-Forwarded-Proto` del balanceador (`Auth__Proxy__TrustAllProxies`) y lee la IP real de `CF-Connecting-IP`.

SQL Server no existe en Render: la base de datos es externa (Azure SQL, SQL Server en VM o en las instalaciones de AddACCION).

## Variables de entorno

### Obligatorias

| Variable | Valor | Cómo obtenerlo |
|---|---|---|
| `ConnectionStrings__AuthDb` | `Server=tcp:<host>,1433;Database=AddAccionAuth;User ID=addaccion_auth;Password=<secreto>;Encrypt=True;TrustServerCertificate=False;Connect Timeout=15` | Login con el rol `auth_service` ([permisos](../db/examples/permissions.example.sql)), nunca `sa`. `TrustServerCertificate=False`: el servidor debe tener un certificado válido |
| `Auth__Issuer` | `https://addaccion-auth.onrender.com` o el dominio propio `https://auth.addaccion.com` | Sin `/` final. Va dentro de todos los tokens: **decidirlo antes de producción y no cambiarlo**. Si habrá dominio propio, configurarlo desde el principio |
| `Auth__SigningKeys__Inline__0` | Clave privada de firma en base64 (una línea) | `docker run --rm addaccion-auth generate-key --type ec --base64` (o `dotnet run --project src/AddAccion.Auth -- generate-key --type ec --base64`). Pegarla en Render y no guardarla en ningún otro sitio que no sea el gestor de secretos |
| `Auth__Login__CsrfKey` | base64 de 32 bytes | Lo genera Render (`generateValue` en `render.yaml`) o `openssl rand -base64 32` |
| `Auth__Proxy__TrustAllProxies` | `true` | Fijo en Render |
| `Auth__Proxy__ClientIpHeader` | `CF-Connecting-IP` | Fijo en Render |

`Auth__SigningKeys__ActiveKey` = `inline-0` (valor por defecto, se puede omitir).

No definir: `PORT` (lo pone Render), `ASPNETCORE_ENVIRONMENT` (la imagen ya trae `Production`), `Auth__SigningKeys__Path` (incompatible con `Inline`).

### Opcionales

| Variable | Cuándo |
|---|---|
| `Auth__Cors__AllowedOrigins__0`, `__1`… | SPAs que llaman a `/oauth2/token` desde el navegador. Orígenes exactos: `https://portal.addaccion.com` |
| `Auth__SigningKeys__Inline__1` | Durante una rotación de clave (ver abajo) o para publicar además una clave RSA (`generate-key --type rsa --base64`) si algún sistema solo acepta RS256 |
| `Auth__Users__UseVarcharParameters` | `true` si la columna de login de la tabla de usuarios es `varchar` |
| `Auth__Login__MaxFailedAttempts` / `Auth__Login__LockoutSeconds` | Cambiar la política de bloqueo (5 / 900 por defecto) |
| `Auth__RateLimits__LoginPermitsPerWindow`, `Auth__RateLimits__TokenPerSecond`, `Auth__RateLimits__TokenBurst` | Ajustar los límites por IP (10 logins/min; 50 tokens/s con ráfaga de 100) |
| `PUBLISH_AOT` | `false` solo si el build de Render falla por memoria al compilar AOT. Imagen alternativa: 251 MB y arranque más lento |
| `ConnectionStrings__AuthDbMigrations` | Solo si se activa `preDeployCommand` (ver paso 2) |

## Pasos

1. **Base de datos.** Crear la BD `AddAccionAuth`, el login `addaccion_auth` con el rol de [`permissions.example.sql`](../db/examples/permissions.example.sql) y las vistas `auth.vw_Users` / `auth.vw_UserRoles` sobre las tablas reales ([contrato](usuarios-sql-server.md)). Firewall: permitir las IPs de salida de Render (Dashboard → servicio → *Connect* → *Outbound*). Las IPs por defecto se comparten con otros clientes de la misma región; para una lista de permitidos estricta, contratar *Dedicated IPs* (plan Pro).

2. **Esquema.** Desde una máquina de confianza, con una identidad con permisos DDL:
   ```bash
   docker build -t addaccion-auth .
   docker run --rm -e ConnectionStrings__AuthDb='<cadena con permisos DDL>' addaccion-auth migrate
   ```
   Alternativa automática: descomentar `preDeployCommand` en `render.yaml` y definir `ConnectionStrings__AuthDbMigrations`. Requiere plan de pago, y esa credencial privilegiada queda también en el entorno del servicio en ejecución.

3. **Clave de firma.** `docker run --rm addaccion-auth generate-key --type ec --base64` → valor de `Auth__SigningKeys__Inline__0`.

4. **Servicio.** Render → *New* → *Blueprint* → este repositorio (usa [`render.yaml`](../render.yaml)), e introducir las variables `sync: false`. Sin Blueprint: *New* → *Web Service* → *Docker*, *Health Check Path* `/health/ready` y las variables de la tabla.

5. **Verificación.**
   ```bash
   curl https://addaccion-auth.onrender.com/.well-known/openid-configuration   # "issuer" igual a Auth__Issuer
   curl https://addaccion-auth.onrender.com/health/ready                        # Healthy
   ```
   En los logs de Render deben aparecer `Loaded signing key inline-0 kid=…` y `Now listening on: http://0.0.0.0:10000`. Un login fallido debe registrar `ip=<IP pública real>`. Si aparece una IP interna de Render, `CF-Connecting-IP` no está llegando: quitar `Auth__Proxy__ClientIpHeader` y tratar el rate limit por IP como global.

6. **Primer cliente administrador** (desde la máquina del paso 2, contra la misma BD):
   ```bash
   docker run --rm -e ConnectionStrings__AuthDb='<cadena>' addaccion-auth \
     create-client --id auth-admin --name "Administración" --grants client_credentials --scopes auth.admin
   ```

7. **Dominio propio** (`auth.addaccion.com`): Settings → Custom Domains, y `Auth__Issuer` con ese dominio **antes** de emitir tokens en producción.

## Rotación de la clave de firma

1. Añadir `Auth__SigningKeys__Inline__1` con la clave nueva y desplegar. Se publica en JWKS pero no firma.
2. A las 24 h, cambiar `Auth__SigningKeys__ActiveKey` a `inline-1` y desplegar.
3. Pasadas otras 24 h (vida máxima de un access token), mover la nueva a `Inline__0`, borrar `Inline__1`, volver `ActiveKey` a `inline-0` y desplegar.

## Comportamiento en Render

- **Varias instancias:** todas deben compartir `Auth__Login__CsrfKey` y las claves de firma. Con variables del servicio ya ocurre. El rate limit es por instancia.
- **Plan free:** el servicio se duerme a los 15 min sin tráfico. La app arranca en ~90 ms, pero la reactivación de Render tarda decenas de segundos. Un servidor de tokens no debe estar en plan free en producción.
- **Health check:** `/health/ready` comprueba la conexión a SQL Server y las vistas de usuarios. Si la BD no responde, Render no envía tráfico a la instancia nueva y el despliegue anterior sigue activo.
- **Logs:** JSON por línea. Ver los `EventId` de seguridad en [operación](operacion.md#monitorización); conectar un *Log Stream* de Render al SIEM.
- **Secret Files de Render:** no usarlos para las claves. Se montan con permisos que el usuario no root de la imagen puede no poder leer; por eso las claves van en variables de entorno.
