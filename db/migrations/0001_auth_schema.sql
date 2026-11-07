-- =============================================================================
-- AddACCION Auth - schema 0001
-- Owns only objects in schema [auth]. Never touches the existing user tables:
-- users are read through the views auth.vw_Users / auth.vw_UserRoles
-- (see db/examples/user_views.example.sql), which the DBA maps onto the
-- existing AddACCION user tables.
--
-- Identifiers, hashes and URIs use a binary collation: OAuth requires exact,
-- case-sensitive comparison (client_id, redirect_uri, scope, jti).
-- All timestamps are UTC (datetime2(3)).
-- Idempotent: safe to run more than once. Batches separated by GO.
-- =============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_PADDING ON;
SET ANSI_WARNINGS ON;
SET ARITHABORT ON;
SET CONCAT_NULL_YIELDS_NULL ON;
SET NUMERIC_ROUNDABORT OFF;
GO

IF SCHEMA_ID(N'auth') IS NULL
    EXEC(N'CREATE SCHEMA auth AUTHORIZATION dbo');
GO

IF OBJECT_ID(N'auth.SchemaVersions', N'U') IS NULL
CREATE TABLE auth.SchemaVersions
(
    Version      int           NOT NULL CONSTRAINT PK_SchemaVersions PRIMARY KEY,
    Name         nvarchar(200) NOT NULL,
    AppliedAtUtc datetime2(3)  NOT NULL CONSTRAINT DF_SchemaVersions_AppliedAt DEFAULT SYSUTCDATETIME()
);
GO

-- -----------------------------------------------------------------------------
-- Scopes / API resources. Audience = value placed in the access token "aud".
-- -----------------------------------------------------------------------------
IF OBJECT_ID(N'auth.Scopes', N'U') IS NULL
CREATE TABLE auth.Scopes
(
    Name        varchar(200)  COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT PK_Scopes PRIMARY KEY,
    Audience    varchar(500)  COLLATE Latin1_General_100_BIN2 NOT NULL,
    Description nvarchar(500) NULL,
    IsEnabled   bit           NOT NULL CONSTRAINT DF_Scopes_IsEnabled DEFAULT 1
);
GO

-- -----------------------------------------------------------------------------
-- Clients (external systems, SPAs, mobile apps, internal services).
-- ClientType: 1 = confidential, 2 = public.
-- TokenEndpointAuthMethod: client_secret_basic | client_secret_post | private_key_jwt | none
-- AllowedGrantTypes: space separated (authorization_code refresh_token client_credentials)
-- Jwks: JSON Web Key Set (public keys) for private_key_jwt.
-- -----------------------------------------------------------------------------
IF OBJECT_ID(N'auth.Clients', N'U') IS NULL
CREATE TABLE auth.Clients
(
    ClientId                    varchar(100)  COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT PK_Clients PRIMARY KEY,
    ClientName                  nvarchar(200) NOT NULL,
    ClientType                  tinyint       NOT NULL CONSTRAINT CK_Clients_ClientType CHECK (ClientType IN (1, 2)),
    TokenEndpointAuthMethod     varchar(40)   COLLATE Latin1_General_100_BIN2 NOT NULL
        CONSTRAINT CK_Clients_AuthMethod CHECK (TokenEndpointAuthMethod IN ('client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none')),
    AllowedGrantTypes           varchar(400)  COLLATE Latin1_General_100_BIN2 NOT NULL,
    Jwks                        nvarchar(max) NULL,
    AccessTokenLifetimeSeconds  int           NOT NULL CONSTRAINT DF_Clients_AtLifetime DEFAULT 600
        CONSTRAINT CK_Clients_AtLifetime CHECK (AccessTokenLifetimeSeconds BETWEEN 60 AND 86400),
    RefreshTokenLifetimeSeconds int           NOT NULL CONSTRAINT DF_Clients_RtLifetime DEFAULT 2592000
        CONSTRAINT CK_Clients_RtLifetime CHECK (RefreshTokenLifetimeSeconds BETWEEN 300 AND 31536000),
    CanIntrospect               bit           NOT NULL CONSTRAINT DF_Clients_CanIntrospect DEFAULT 0,
    IsEnabled                   bit           NOT NULL CONSTRAINT DF_Clients_IsEnabled DEFAULT 1,
    CreatedAtUtc                datetime2(3)  NOT NULL CONSTRAINT DF_Clients_CreatedAt DEFAULT SYSUTCDATETIME(),
    UpdatedAtUtc                datetime2(3)  NOT NULL CONSTRAINT DF_Clients_UpdatedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT CK_Clients_PublicHasNoAuth CHECK ((ClientType = 2 AND TokenEndpointAuthMethod = 'none') OR (ClientType = 1 AND TokenEndpointAuthMethod <> 'none'))
);
GO

-- Secrets are server-generated (256 bits of entropy) and stored as SHA-256.
-- Several active secrets per client allow zero-downtime rotation.
IF OBJECT_ID(N'auth.ClientSecrets', N'U') IS NULL
CREATE TABLE auth.ClientSecrets
(
    Id           int           IDENTITY(1, 1) NOT NULL CONSTRAINT PK_ClientSecrets PRIMARY KEY,
    ClientId     varchar(100)  COLLATE Latin1_General_100_BIN2 NOT NULL
        CONSTRAINT FK_ClientSecrets_Clients REFERENCES auth.Clients (ClientId) ON DELETE CASCADE,
    SecretHash   binary(32)    NOT NULL,
    Description  nvarchar(200) NULL,
    CreatedAtUtc datetime2(3)  NOT NULL CONSTRAINT DF_ClientSecrets_CreatedAt DEFAULT SYSUTCDATETIME(),
    ExpiresAtUtc datetime2(3)  NULL
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_ClientSecrets_ClientId' AND object_id = OBJECT_ID(N'auth.ClientSecrets'))
    CREATE INDEX IX_ClientSecrets_ClientId ON auth.ClientSecrets (ClientId) INCLUDE (SecretHash, ExpiresAtUtc);
GO

IF OBJECT_ID(N'auth.ClientRedirectUris', N'U') IS NULL
CREATE TABLE auth.ClientRedirectUris
(
    Id          int            IDENTITY(1, 1) NOT NULL CONSTRAINT PK_ClientRedirectUris PRIMARY KEY,
    ClientId    varchar(100)   COLLATE Latin1_General_100_BIN2 NOT NULL
        CONSTRAINT FK_ClientRedirectUris_Clients REFERENCES auth.Clients (ClientId) ON DELETE CASCADE,
    RedirectUri nvarchar(2000) COLLATE Latin1_General_100_BIN2 NOT NULL
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_ClientRedirectUris_ClientId' AND object_id = OBJECT_ID(N'auth.ClientRedirectUris'))
    CREATE INDEX IX_ClientRedirectUris_ClientId ON auth.ClientRedirectUris (ClientId) INCLUDE (RedirectUri);
GO

IF OBJECT_ID(N'auth.ClientScopes', N'U') IS NULL
CREATE TABLE auth.ClientScopes
(
    ClientId varchar(100) COLLATE Latin1_General_100_BIN2 NOT NULL
        CONSTRAINT FK_ClientScopes_Clients REFERENCES auth.Clients (ClientId) ON DELETE CASCADE,
    Scope    varchar(200) COLLATE Latin1_General_100_BIN2 NOT NULL,
    CONSTRAINT PK_ClientScopes PRIMARY KEY (ClientId, Scope)
);
GO

-- -----------------------------------------------------------------------------
-- Authorization codes: single use, ~60 s lifetime. Only the SHA-256 is stored.
-- RefreshFamilyId / AccessTokenJti are recorded on redemption so a replayed
-- code revokes everything issued from it (RFC 9700 / OAuth 2.1).
-- -----------------------------------------------------------------------------
IF OBJECT_ID(N'auth.AuthorizationCodes', N'U') IS NULL
CREATE TABLE auth.AuthorizationCodes
(
    Id                  bigint           IDENTITY(1, 1) NOT NULL CONSTRAINT PK_AuthorizationCodes PRIMARY KEY,
    CodeHash            binary(32)       NOT NULL,
    ClientId            varchar(100)     COLLATE Latin1_General_100_BIN2 NOT NULL,
    UserId              nvarchar(128)    NOT NULL,
    RedirectUri         nvarchar(2000)   COLLATE Latin1_General_100_BIN2 NOT NULL,
    Scopes              varchar(2000)    COLLATE Latin1_General_100_BIN2 NOT NULL,
    CodeChallenge       varchar(128)     COLLATE Latin1_General_100_BIN2 NOT NULL,
    Nonce               nvarchar(512)    NULL,
    AuthTimeUtc         datetime2(3)     NOT NULL,
    CreatedAtUtc        datetime2(3)     NOT NULL,
    ExpiresAtUtc        datetime2(3)     NOT NULL,
    ConsumedAtUtc       datetime2(3)     NULL,
    RefreshFamilyId     uniqueidentifier NULL,
    AccessTokenJti      varchar(64)      COLLATE Latin1_General_100_BIN2 NULL,
    AccessTokenExpUtc   datetime2(3)     NULL
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UX_AuthorizationCodes_CodeHash' AND object_id = OBJECT_ID(N'auth.AuthorizationCodes'))
    CREATE UNIQUE INDEX UX_AuthorizationCodes_CodeHash ON auth.AuthorizationCodes (CodeHash);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_AuthorizationCodes_ExpiresAt' AND object_id = OBJECT_ID(N'auth.AuthorizationCodes'))
    CREATE INDEX IX_AuthorizationCodes_ExpiresAt ON auth.AuthorizationCodes (ExpiresAtUtc);
GO

-- -----------------------------------------------------------------------------
-- Refresh tokens: opaque, rotated on every use, stored as SHA-256.
-- FamilyId groups a rotation chain; reuse of a consumed token revokes the family.
-- ExpiresAtUtc is the absolute family expiry (inherited across rotations).
-- -----------------------------------------------------------------------------
IF OBJECT_ID(N'auth.RefreshTokens', N'U') IS NULL
CREATE TABLE auth.RefreshTokens
(
    Id            bigint           IDENTITY(1, 1) NOT NULL CONSTRAINT PK_RefreshTokens PRIMARY KEY,
    TokenHash     binary(32)       NOT NULL,
    FamilyId      uniqueidentifier NOT NULL,
    ClientId      varchar(100)     COLLATE Latin1_General_100_BIN2 NOT NULL,
    UserId        nvarchar(128)    NOT NULL,
    Scopes        varchar(2000)    COLLATE Latin1_General_100_BIN2 NOT NULL,
    AuthTimeUtc   datetime2(3)     NOT NULL,
    CreatedAtUtc  datetime2(3)     NOT NULL,
    ExpiresAtUtc  datetime2(3)     NOT NULL,
    ConsumedAtUtc datetime2(3)     NULL,
    RevokedAtUtc  datetime2(3)     NULL
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UX_RefreshTokens_TokenHash' AND object_id = OBJECT_ID(N'auth.RefreshTokens'))
    CREATE UNIQUE INDEX UX_RefreshTokens_TokenHash ON auth.RefreshTokens (TokenHash);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_RefreshTokens_FamilyId' AND object_id = OBJECT_ID(N'auth.RefreshTokens'))
    CREATE INDEX IX_RefreshTokens_FamilyId ON auth.RefreshTokens (FamilyId);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_RefreshTokens_ExpiresAt' AND object_id = OBJECT_ID(N'auth.RefreshTokens'))
    CREATE INDEX IX_RefreshTokens_ExpiresAt ON auth.RefreshTokens (ExpiresAtUtc);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_RefreshTokens_UserId' AND object_id = OBJECT_ID(N'auth.RefreshTokens'))
    CREATE INDEX IX_RefreshTokens_UserId ON auth.RefreshTokens (UserId) WHERE RevokedAtUtc IS NULL;
GO

-- Revoked JWT access tokens (deny-list by jti, kept until token expiry).
IF OBJECT_ID(N'auth.RevokedAccessTokens', N'U') IS NULL
CREATE TABLE auth.RevokedAccessTokens
(
    Jti          varchar(64)  COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT PK_RevokedAccessTokens PRIMARY KEY,
    ExpiresAtUtc datetime2(3) NOT NULL,
    RevokedAtUtc datetime2(3) NOT NULL CONSTRAINT DF_RevokedAccessTokens_RevokedAt DEFAULT SYSUTCDATETIME()
);
GO

-- Replay protection for private_key_jwt client assertions (RFC 7523 jti).
IF OBJECT_ID(N'auth.ClientAssertionJtis', N'U') IS NULL
CREATE TABLE auth.ClientAssertionJtis
(
    ClientId     varchar(100) COLLATE Latin1_General_100_BIN2 NOT NULL,
    Jti          varchar(256) COLLATE Latin1_General_100_BIN2 NOT NULL,
    ExpiresAtUtc datetime2(3) NOT NULL,
    CONSTRAINT PK_ClientAssertionJtis PRIMARY KEY (ClientId, Jti)
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_ClientAssertionJtis_ExpiresAt' AND object_id = OBJECT_ID(N'auth.ClientAssertionJtis'))
    CREATE INDEX IX_ClientAssertionJtis_ExpiresAt ON auth.ClientAssertionJtis (ExpiresAtUtc);
GO

-- Brute-force protection state, kept apart from the existing user tables.
IF OBJECT_ID(N'auth.UserLoginState', N'U') IS NULL
CREATE TABLE auth.UserLoginState
(
    UserId          nvarchar(128) NOT NULL CONSTRAINT PK_UserLoginState PRIMARY KEY,
    FailedCount     int           NOT NULL CONSTRAINT DF_UserLoginState_FailedCount DEFAULT 0,
    LockoutEndUtc   datetime2(3)  NULL,
    LastFailureUtc  datetime2(3)  NULL,
    LastSuccessUtc  datetime2(3)  NULL
);
GO

-- Built-in scope protecting the administration API.
IF NOT EXISTS (SELECT 1 FROM auth.Scopes WHERE Name = 'auth.admin')
    INSERT INTO auth.Scopes (Name, Audience, Description) VALUES ('auth.admin', 'urn:addaccion:auth:admin', N'Administración de clientes OAuth');
GO

IF NOT EXISTS (SELECT 1 FROM auth.SchemaVersions WHERE Version = 1)
    INSERT INTO auth.SchemaVersions (Version, Name) VALUES (1, N'0001_auth_schema');
GO
