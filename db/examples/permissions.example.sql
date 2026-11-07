-- =============================================================================
-- Least privilege for the service account (OWASP ASVS V1.4 / V14).
-- The service needs: DML on its own tables, SELECT on the user views. Nothing on dbo.
-- Schema changes are applied by a separate, privileged migration identity
-- (CLI "migrate" with a different connection string, or a DBA pipeline).
-- =============================================================================
IF DATABASE_PRINCIPAL_ID(N'auth_service') IS NULL
    CREATE ROLE auth_service;
GO
GRANT SELECT, INSERT, UPDATE, DELETE ON SCHEMA::auth TO auth_service;
DENY  ALTER, CONTROL, REFERENCES      ON SCHEMA::auth TO auth_service;
-- Views read the base tables through ownership chaining (same owner, dbo),
-- so no grant on dbo tables is required.
GO
-- Example login/user (use Entra ID / managed identity when possible instead of SQL auth):
-- CREATE LOGIN addaccion_auth WITH PASSWORD = '<from secret store>', CHECK_POLICY = ON;
-- CREATE USER  addaccion_auth FOR LOGIN addaccion_auth;
-- ALTER ROLE auth_service ADD MEMBER addaccion_auth;
