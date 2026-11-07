-- =============================================================================
-- AddACCION Auth - USER VIEW CONTRACT
--
-- The service never reads the AddACCION user tables directly. It reads these
-- two views, which the DBA must create (or adapt) over the existing tables.
-- Changing the underlying tables only requires changing the views.
--
-- auth.vw_Users  (one row per user)
--   UserId         nvarchar(128)  NOT NULL  stable, never reused -> "sub" claim
--   LoginName      nvarchar(256)  NOT NULL  value typed in the login form (username or email), UNIQUE
--   Email          nvarchar(256)  NULL
--   EmailVerified  bit            NOT NULL
--   DisplayName    nvarchar(256)  NULL
--   GivenName      nvarchar(128)  NULL
--   FamilyName     nvarchar(128)  NULL
--   PasswordHash   nvarchar(1024) NULL      supported formats: see docs/usuarios-sql-server.md
--   IsActive       bit            NOT NULL  0 = cannot log in, refresh tokens stop working
--
-- auth.vw_UserRoles (zero or more rows per user)
--   UserId         nvarchar(128)  NOT NULL
--   RoleName       nvarchar(128)  NOT NULL  -> "roles" claim
--
-- Performance: the service filters with equality predicates on LoginName and
-- UserId. Both must map to INDEXED base columns WITHOUT functions/conversions
-- in the view, otherwise every login/refresh becomes a table scan:
--   * key is int/uniqueidentifier -> add a PERSISTED computed column
--     CONVERT(nvarchar(128), Id) with a unique index (as in the example below).
--   * login column is varchar (not nvarchar) -> set Auth:Users:UseVarcharParameters=true
--     so parameters are sent as varchar and no implicit conversion happens.
-- =============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_PADDING ON;
SET ANSI_WARNINGS ON;
SET ARITHABORT ON;
SET CONCAT_NULL_YIELDS_NULL ON;
SET NUMERIC_ROUNDABORT OFF;
GO

-- ---------------------------------------------------------------------------
-- EXAMPLE base table (only for development / tests). Do NOT run in production:
-- production maps the views to the real AddACCION tables instead.
-- ---------------------------------------------------------------------------
IF OBJECT_ID(N'dbo.AppUsers', N'U') IS NULL
CREATE TABLE dbo.AppUsers
(
    Id             uniqueidentifier NOT NULL CONSTRAINT PK_AppUsers PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    UserName       nvarchar(256)    NOT NULL CONSTRAINT UX_AppUsers_UserName UNIQUE,
    Email          nvarchar(256)    NULL,
    EmailConfirmed bit              NOT NULL DEFAULT 0,
    FirstName      nvarchar(128)    NULL,
    LastName       nvarchar(128)    NULL,
    PasswordHash   nvarchar(1024)   NULL,
    Active         bit              NOT NULL DEFAULT 1,
    -- Persisted text form of the key so "WHERE UserId = @id" on the view is an index seek.
    UserKey        AS CONVERT(nvarchar(128), Id) PERSISTED NOT NULL
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UX_AppUsers_UserKey' AND object_id = OBJECT_ID(N'dbo.AppUsers'))
    CREATE UNIQUE INDEX UX_AppUsers_UserKey ON dbo.AppUsers (UserKey);
GO
IF OBJECT_ID(N'dbo.AppUserRoles', N'U') IS NULL
CREATE TABLE dbo.AppUserRoles
(
    UserKey  nvarchar(128) NOT NULL,
    RoleName nvarchar(128) NOT NULL,
    CONSTRAINT PK_AppUserRoles PRIMARY KEY (UserKey, RoleName)
);
GO

-- ---------------------------------------------------------------------------
-- The views (adapt the FROM / column expressions to the real tables).
-- ---------------------------------------------------------------------------
CREATE OR ALTER VIEW auth.vw_Users
AS
SELECT
    u.UserKey                                            AS UserId,
    u.UserName                                           AS LoginName,
    u.Email                                              AS Email,
    u.EmailConfirmed                                     AS EmailVerified,
    NULLIF(LTRIM(RTRIM(CONCAT(u.FirstName, N' ', u.LastName))), N'') AS DisplayName,
    u.FirstName                                          AS GivenName,
    u.LastName                                           AS FamilyName,
    u.PasswordHash                                       AS PasswordHash,
    u.Active                                             AS IsActive
FROM dbo.AppUsers AS u;
GO

CREATE OR ALTER VIEW auth.vw_UserRoles
AS
SELECT r.UserKey AS UserId, r.RoleName AS RoleName
FROM dbo.AppUserRoles AS r;
GO
