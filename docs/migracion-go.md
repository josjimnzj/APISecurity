# Migración a Go

## Conclusión con datos

El motivo declarado para Go era rendimiento y cold start en contenedores. Medido en este repositorio con .NET 10 Native AOT:

| Métrica | .NET 10 Native AOT (medido aquí) | Referencia típica Go (orientativa, no medida aquí) |
|---|---|---|
| Arranque proceso → primera respuesta | ~90 ms | 10–50 ms |
| `docker run` → ready con conexión a SQL Server | ~400 ms | dominado por el arranque del contenedor y la conexión TLS a la BD, similar |
| RSS en reposo | ~47 MB (17 MiB según cgroup) | 10–25 MB |
| Throughput `client_credentials` ES256 | ~18.900 req/s en 4 vCPU compartidas | del mismo orden: el coste dominante es la firma ECDSA, no el lenguaje |
| Binario | 25 MB, sin runtime externo | 15–25 MB |

El cuello de botella real es criptográfico (firma por token) y de I/O a SQL Server, no del runtime. El salto que justificaba Go (JIT frío, ~1–2 s de arranque, 150+ MB) ya está eliminado por Native AOT. **Recomendación: no migrar por rendimiento.** Revaluar solo si (a) el equipo es mayoritariamente Go, o (b) se mide en producción un problema concreto que Go resuelva (p. ej. densidad de miles de réplicas con escala a cero).

Antes de decidir, medir en la plataforma real: `deploy/kubernetes` + el generador de carga que se prefiera contra `/oauth2/token`.

## Si se migra: el contrato ya está separado del lenguaje

Una implementación Go puede sustituir a la .NET réplica a réplica (rolling) si respeta:

| Contrato | Dónde | Detalle |
|---|---|---|
| API HTTP | RFCs listados en el README + `/admin/v1` | Mismos paths, códigos de estado, errores `{"error","error_description"}` |
| Esquema de BD | `db/migrations/*.sql` | Mismo esquema; ambas versiones pueden convivir sobre la misma BD durante la migración |
| Vistas de usuarios | `auth.vw_Users`, `auth.vw_UserRoles` | Sin cambios para el DBA |
| SQL | `Persistence/SqlServer/*.cs` | SQL portable literalmente (driver `github.com/microsoft/go-mssqldb`); conservar tipos y tamaños de parámetros (`varchar(100)`, `binary(32)`…) para reutilizar planes y no romper los índices |
| Claves de firma | PEM PKCS#8 en directorio, `kid` = RFC 7638 base64url | Go calcula el mismo `kid` ⇒ los tokens emitidos por ambas versiones validan contra el mismo JWKS |
| Hash de valores opacos | SHA‑256 de UTF‑8, `binary(32)` | Secretos `aasec_` + base64url(32 bytes); códigos/refresh base64url(32 bytes) |
| Contraseñas | Formato ASP.NET Identity v2/v3 | Reimplementar `IdentityPasswordHashVerifier` (≈60 líneas con `golang.org/x/crypto/pbkdf2`) |
| CSRF del login | HMAC‑SHA256 con clave `HKDF-SHA256(CsrfKey, salt="", info="addaccion-auth/login-csrf/v1")` | Cookie `__Host-aa_csrf`; permite mezclar réplicas .NET y Go durante el rollout |
| Claims | Ver [integración](integracion.md) | Mismos nombres y semántica |

## Verificación: suite de conformidad

`tests/AddAccion.Auth.Tests/Http/ProtocolTests.cs` es de caja negra (solo HTTP + siembra de datos en SQL Server). Ejecutarla contra la versión Go:

```bash
# servidor Go escuchando en :5199 sobre la BD AddAccionAuthGo, con MaxFailedAttempts=3 y rate limit desactivado
AUTH_TEST_BASE_URL=http://127.0.0.1:5199 \
AUTH_TEST_EXTERNAL_DB='Server=localhost,1433;Database=AddAccionAuthGo;User ID=sa;Password=…;Encrypt=True;TrustServerCertificate=True' \
dotnet test --filter ExternalProtocolTests
```

Criterio de aceptación de la migración: 100 % de la suite en verde + mismas métricas de carga o mejores en la plataforma real.

## Equivalencias de librerías

| Función | .NET | Go |
|---|---|---|
| HTTP | Kestrel / Minimal APIs | `net/http` (1.22+ router) |
| SQL Server | Microsoft.Data.SqlClient | `github.com/microsoft/go-mssqldb` |
| JWT / JWK | Microsoft.IdentityModel.JsonWebTokens | `github.com/go-jose/go-jose/v4` o `github.com/lestrrat-go/jwx/v2` |
| PBKDF2 / HKDF | `System.Security.Cryptography` | `golang.org/x/crypto/pbkdf2`, `golang.org/x/crypto/hkdf` |
| Rate limit | `Microsoft.AspNetCore.RateLimiting` | `golang.org/x/time/rate` |
| Métricas | `System.Diagnostics.Metrics` | OpenTelemetry Go |
