# Usuarios en SQL Server

El servicio **no lee ni escribe** las tablas de usuarios existentes. Lee dos vistas con un contrato fijo que el DBA crea sobre las tablas reales. Cambiar el esquema de usuarios solo exige cambiar las vistas.

## Contrato

`auth.vw_Users` — una fila por usuario

| Columna | Tipo | Notas |
|---|---|---|
| `UserId` | `nvarchar(128)` | Estable y nunca reutilizado. Es el claim `sub`. |
| `LoginName` | `nvarchar(256)` | Lo que el usuario escribe (usuario o email). **Único.** |
| `Email` | `nvarchar(256)` NULL | Claim `email` (scope `email`) |
| `EmailVerified` | `bit` | Claim `email_verified` |
| `DisplayName`, `GivenName`, `FamilyName` | `nvarchar` NULL | Claims `name`, `given_name`, `family_name` (scope `profile`) |
| `PasswordHash` | `nvarchar(1024)` NULL | Ver formatos soportados |
| `IsActive` | `bit` | `0` = no puede iniciar sesión y sus refresh tokens dejan de funcionar en el siguiente uso |

`auth.vw_UserRoles` — cero o más filas por usuario: `UserId`, `RoleName` → claim `roles` (scope `roles`).

Ejemplo completo con tabla de prueba: [`db/examples/user_views.example.sql`](../db/examples/user_views.example.sql).

## Rendimiento: obligatorio

El servicio filtra con igualdad por `LoginName` (login) y `UserId` (canje de código, refresh, userinfo). Ambas columnas de la vista deben mapear **directamente** a columnas indexadas de la tabla base:

- Clave `int`/`uniqueidentifier`: añadir columna calculada persistida e indexarla, en vez de `CONVERT` en la vista.
  ```sql
  ALTER TABLE dbo.Usuarios ADD UserKey AS CONVERT(nvarchar(128), IdUsuario) PERSISTED;
  CREATE UNIQUE INDEX UX_Usuarios_UserKey ON dbo.Usuarios (UserKey);
  ```
- Columna de login `varchar` (no `nvarchar`): configurar `Auth:Users:UseVarcharParameters=true` para evitar la conversión implícita que anula el índice.
- `LoginName` debe ser único (índice único). Si la vista devuelve dos filas para el mismo login, el servicio lo trata como "no encontrado" y no autentica a ninguno.
- La comparación de `LoginName` sigue la collation de la tabla base (habitualmente insensible a mayúsculas).

Comprobación: el plan de `SELECT * FROM auth.vw_Users WHERE LoginName = @p` y `… WHERE UserId = @p` debe ser un *Index Seek*.

## Formatos de hash de contraseña soportados

| Formato | Detección | Estado |
|---|---|---|
| ASP.NET Core Identity v3 (PBKDF2 HMAC‑SHA1/256/512, iteraciones y sal en el propio hash) | Base64, primer byte `0x01` | Aceptado. Si PRF=SHA1 o < 100.000 iteraciones se registra aviso `WeakPasswordHash` |
| ASP.NET Identity v2 (PBKDF2‑SHA1, 1.000 iteraciones) | Base64, primer byte `0x00` | Aceptado como legado, siempre con aviso |
| Otros (bcrypt, Argon2, SHA‑x, MD5…) | — | Implementar `IPasswordHashVerifier` y registrarlo en DI (`AuthServer.ConfigureServices`) |

El servicio no reescribe hashes (acceso de solo lectura). La migración a un hash más fuerte la hace el sistema dueño de los usuarios en el siguiente cambio de contraseña. Los avisos `WeakPasswordHash` (EventId 2004) listan los usuarios afectados.

Hashes MD5/SHA‑1 sin sal **no deben soportarse**: forzar el restablecimiento de contraseña.

## Bloqueo de cuentas

El estado de intentos fallidos vive en `auth.UserLoginState`, no en las tablas de usuarios. Por defecto: 5 fallos consecutivos → bloqueo 15 minutos (`Auth:Login:MaxFailedAttempts`, `Auth:Login:LockoutSeconds`). Durante el bloqueo, incluso la contraseña correcta se rechaza con el mismo mensaje genérico. Desbloqueo manual:

```sql
DELETE FROM auth.UserLoginState WHERE UserId = N'<UserId>';
```

## Permisos

[`db/examples/permissions.example.sql`](../db/examples/permissions.example.sql): rol `auth_service` con DML en el esquema `auth` y lectura de las vistas por *ownership chaining* (sin permisos sobre `dbo`). Las migraciones (`migrate`) se ejecutan con otra identidad con permisos DDL (`ConnectionStrings:AuthDbMigrations`). En Azure SQL usar identidad administrada (`Authentication=Active Directory Managed Identity`) en lugar de usuario/contraseña.
