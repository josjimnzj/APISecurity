using AddAccion.Auth.Domain;
using Microsoft.Data.SqlClient;

namespace AddAccion.Auth.Persistence.SqlServer;

public sealed class SqlClientStore(SqlConnectionFactory db) : IClientStore
{
    private const string FindSql = """
        SELECT ClientId, ClientName, ClientType, TokenEndpointAuthMethod, AllowedGrantTypes, Jwks,
               AccessTokenLifetimeSeconds, RefreshTokenLifetimeSeconds, CanIntrospect, IsEnabled
        FROM auth.Clients WHERE ClientId = @ClientId;
        SELECT Id, SecretHash, Description, CreatedAtUtc, ExpiresAtUtc FROM auth.ClientSecrets WHERE ClientId = @ClientId;
        SELECT RedirectUri FROM auth.ClientRedirectUris WHERE ClientId = @ClientId;
        SELECT Scope FROM auth.ClientScopes WHERE ClientId = @ClientId;
        """;

    public async Task<ClientApplication?> FindAsync(string clientId, CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = SqlConnectionFactory.Command(connection, FindSql);
        cmd.Parameters.Add(Sql.VarChar("@ClientId", clientId, 100));
        await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);

        if (!await r.ReadAsync(ct).ConfigureAwait(false)) return null;

        var id = r.GetString(0);
        var name = r.GetString(1);
        var type = (ClientType)r.GetByte(2);
        var method = r.GetString(3);
        var grants = r.GetString(4).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var jwks = r.StringOrNull(5);
        var atLifetime = r.GetInt32(6);
        var rtLifetime = r.GetInt32(7);
        var canIntrospect = r.GetBoolean(8);
        var enabled = r.GetBoolean(9);

        var secrets = new List<ClientSecretInfo>();
        await r.NextResultAsync(ct).ConfigureAwait(false);
        while (await r.ReadAsync(ct).ConfigureAwait(false))
        {
            secrets.Add(new ClientSecretInfo(r.GetInt32(0), (byte[])r.GetValue(1), r.StringOrNull(2), r.Utc(3), r.UtcOrNull(4)));
        }

        var redirects = new List<string>();
        await r.NextResultAsync(ct).ConfigureAwait(false);
        while (await r.ReadAsync(ct).ConfigureAwait(false)) redirects.Add(r.GetString(0));

        var scopes = new List<string>();
        await r.NextResultAsync(ct).ConfigureAwait(false);
        while (await r.ReadAsync(ct).ConfigureAwait(false)) scopes.Add(r.GetString(0));

        return new ClientApplication
        {
            ClientId = id,
            ClientName = name,
            ClientType = type,
            TokenEndpointAuthMethod = method,
            AllowedGrantTypes = grants,
            RedirectUris = redirects,
            AllowedScopes = scopes,
            Secrets = secrets,
            Jwks = jwks,
            AccessTokenLifetimeSeconds = atLifetime,
            RefreshTokenLifetimeSeconds = rtLifetime,
            CanIntrospect = canIntrospect,
            IsEnabled = enabled,
        };
    }

    public async Task<bool> CreateAsync(ClientApplication client, CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        await using var tx = (SqlTransaction)await connection.BeginTransactionAsync(ct).ConfigureAwait(false);
        try
        {
            await using (var cmd = SqlConnectionFactory.Command(connection, """
                INSERT INTO auth.Clients (ClientId, ClientName, ClientType, TokenEndpointAuthMethod, AllowedGrantTypes, Jwks,
                                          AccessTokenLifetimeSeconds, RefreshTokenLifetimeSeconds, CanIntrospect, IsEnabled)
                VALUES (@ClientId, @ClientName, @ClientType, @Method, @Grants, @Jwks, @AtLifetime, @RtLifetime, @CanIntrospect, @IsEnabled);
                """, tx))
            {
                cmd.Parameters.Add(Sql.VarChar("@ClientId", client.ClientId, 100));
                cmd.Parameters.Add(Sql.NVarChar("@ClientName", client.ClientName, 200));
                cmd.Parameters.Add(Sql.TinyInt("@ClientType", (byte)client.ClientType));
                cmd.Parameters.Add(Sql.VarChar("@Method", client.TokenEndpointAuthMethod, 40));
                cmd.Parameters.Add(Sql.VarChar("@Grants", string.Join(' ', client.AllowedGrantTypes), 400));
                cmd.Parameters.Add(Sql.NVarCharMax("@Jwks", client.Jwks));
                cmd.Parameters.Add(Sql.Int("@AtLifetime", client.AccessTokenLifetimeSeconds));
                cmd.Parameters.Add(Sql.Int("@RtLifetime", client.RefreshTokenLifetimeSeconds));
                cmd.Parameters.Add(Sql.Bit("@CanIntrospect", client.CanIntrospect));
                cmd.Parameters.Add(Sql.Bit("@IsEnabled", client.IsEnabled));
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }

            foreach (var s in client.Secrets)
            {
                await using var cmd = SqlConnectionFactory.Command(connection, """
                    INSERT INTO auth.ClientSecrets (ClientId, SecretHash, Description, CreatedAtUtc, ExpiresAtUtc)
                    VALUES (@ClientId, @Hash, @Description, @CreatedAt, @ExpiresAt);
                    """, tx);
                cmd.Parameters.Add(Sql.VarChar("@ClientId", client.ClientId, 100));
                cmd.Parameters.Add(Sql.Binary32("@Hash", s.SecretHash));
                cmd.Parameters.Add(Sql.NVarChar("@Description", s.Description, 200));
                cmd.Parameters.Add(Sql.DateTime2("@CreatedAt", s.CreatedAt));
                cmd.Parameters.Add(Sql.DateTime2("@ExpiresAt", s.ExpiresAt));
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }

            foreach (var uri in client.RedirectUris)
            {
                await using var cmd = SqlConnectionFactory.Command(connection,
                    "INSERT INTO auth.ClientRedirectUris (ClientId, RedirectUri) VALUES (@ClientId, @Uri);", tx);
                cmd.Parameters.Add(Sql.VarChar("@ClientId", client.ClientId, 100));
                cmd.Parameters.Add(Sql.NVarChar("@Uri", uri, 2000));
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }

            foreach (var scope in client.AllowedScopes)
            {
                await using var cmd = SqlConnectionFactory.Command(connection,
                    "INSERT INTO auth.ClientScopes (ClientId, Scope) VALUES (@ClientId, @Scope);", tx);
                cmd.Parameters.Add(Sql.VarChar("@ClientId", client.ClientId, 100));
                cmd.Parameters.Add(Sql.VarChar("@Scope", scope, 200));
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }

            await tx.CommitAsync(ct).ConfigureAwait(false);
            return true;
        }
        catch (SqlException ex) when (Sql.IsDuplicateKey(ex))
        {
            await tx.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            return false;
        }
    }

    public async Task<int> AddSecretAsync(string clientId, byte[] secretHash, string? description, DateTimeOffset createdAt, DateTimeOffset? expiresAt, CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = SqlConnectionFactory.Command(connection, """
            INSERT INTO auth.ClientSecrets (ClientId, SecretHash, Description, CreatedAtUtc, ExpiresAtUtc)
            OUTPUT inserted.Id
            SELECT ClientId, @Hash, @Description, @CreatedAt, @ExpiresAt FROM auth.Clients WHERE ClientId = @ClientId;
            """);
        cmd.Parameters.Add(Sql.VarChar("@ClientId", clientId, 100));
        cmd.Parameters.Add(Sql.Binary32("@Hash", secretHash));
        cmd.Parameters.Add(Sql.NVarChar("@Description", description, 200));
        cmd.Parameters.Add(Sql.DateTime2("@CreatedAt", createdAt));
        cmd.Parameters.Add(Sql.DateTime2("@ExpiresAt", expiresAt));
        var result = await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
        return result is int id ? id : 0;
    }

    public async Task<bool> DeleteSecretAsync(string clientId, int secretId, CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = SqlConnectionFactory.Command(connection,
            "DELETE FROM auth.ClientSecrets WHERE ClientId = @ClientId AND Id = @Id;");
        cmd.Parameters.Add(Sql.VarChar("@ClientId", clientId, 100));
        cmd.Parameters.Add(Sql.Int("@Id", secretId));
        return await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false) == 1;
    }

    public async Task<bool> SetEnabledAsync(string clientId, bool enabled, DateTimeOffset now, CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = SqlConnectionFactory.Command(connection,
            "UPDATE auth.Clients SET IsEnabled = @Enabled, UpdatedAtUtc = @Now WHERE ClientId = @ClientId;");
        cmd.Parameters.Add(Sql.VarChar("@ClientId", clientId, 100));
        cmd.Parameters.Add(Sql.Bit("@Enabled", enabled));
        cmd.Parameters.Add(Sql.DateTime2("@Now", now));
        return await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false) == 1;
    }
}

public sealed class SqlScopeStore(SqlConnectionFactory db) : IScopeStore
{
    public async Task<IReadOnlyList<ScopeDefinition>> GetAllAsync(CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = SqlConnectionFactory.Command(connection, "SELECT Name, Audience, Description, IsEnabled FROM auth.Scopes;");
        await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        var list = new List<ScopeDefinition>();
        while (await r.ReadAsync(ct).ConfigureAwait(false))
        {
            list.Add(new ScopeDefinition(r.GetString(0), r.GetString(1), r.StringOrNull(2), r.GetBoolean(3)));
        }
        return list;
    }
}

public sealed class SqlDatabaseHealth(SqlConnectionFactory db) : IDatabaseHealth
{
    public async Task<bool> PingAsync(CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        // Also proves the user views exist and are readable by the service account.
        await using var cmd = SqlConnectionFactory.Command(connection, """
            SELECT TOP (0) ClientId FROM auth.Clients;
            SELECT TOP (0) UserId, LoginName FROM auth.vw_Users;
            SELECT TOP (0) UserId, RoleName FROM auth.vw_UserRoles;
            """);
        await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return true;
    }
}
