using AddAccion.Auth.Domain;
using Microsoft.Data.SqlClient;

namespace AddAccion.Auth.Persistence.SqlServer;

public sealed class SqlGrantStore(SqlConnectionFactory db) : IGrantStore
{
    public async Task CreateAuthorizationCodeAsync(AuthorizationCodeRecord code, CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = SqlConnectionFactory.Command(connection, """
            INSERT INTO auth.AuthorizationCodes (CodeHash, ClientId, UserId, RedirectUri, Scopes, CodeChallenge, Nonce, AuthTimeUtc, CreatedAtUtc, ExpiresAtUtc)
            VALUES (@Hash, @ClientId, @UserId, @RedirectUri, @Scopes, @Challenge, @Nonce, @AuthTime, @CreatedAt, @ExpiresAt);
            """);
        cmd.Parameters.Add(Sql.Binary32("@Hash", code.CodeHash));
        cmd.Parameters.Add(Sql.VarChar("@ClientId", code.ClientId, 100));
        cmd.Parameters.Add(Sql.NVarChar("@UserId", code.UserId, 128));
        cmd.Parameters.Add(Sql.NVarChar("@RedirectUri", code.RedirectUri, 2000));
        cmd.Parameters.Add(Sql.VarChar("@Scopes", code.Scopes, 2000));
        cmd.Parameters.Add(Sql.VarChar("@Challenge", code.CodeChallenge, 128));
        cmd.Parameters.Add(Sql.NVarChar("@Nonce", code.Nonce, 512));
        cmd.Parameters.Add(Sql.DateTime2("@AuthTime", code.AuthTime));
        cmd.Parameters.Add(Sql.DateTime2("@CreatedAt", code.CreatedAt));
        cmd.Parameters.Add(Sql.DateTime2("@ExpiresAt", code.ExpiresAt));
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    public async Task<CodeRedemptionResult> RedeemAuthorizationCodeAsync(CodeRedemption redemption, CancellationToken ct)
    {
        var x = redemption;
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        // One round trip: conditional consume; on miss, report whether it was a replay of a consumed code.
        await using var cmd = SqlConnectionFactory.Command(connection, """
            UPDATE auth.AuthorizationCodes
               SET ConsumedAtUtc = @Now, RefreshFamilyId = @FamilyId, AccessTokenJti = @Jti, AccessTokenExpUtc = @AtExp
            OUTPUT inserted.Id, inserted.UserId, inserted.Scopes, inserted.Nonce, inserted.AuthTimeUtc, inserted.CreatedAtUtc, inserted.ExpiresAtUtc
             WHERE CodeHash = @Hash AND ConsumedAtUtc IS NULL AND ExpiresAtUtc > @Now
               AND ClientId = @ClientId AND RedirectUri = @RedirectUri AND CodeChallenge = @Challenge;
            IF @@ROWCOUNT = 0
                SELECT ConsumedAtUtc, RefreshFamilyId, AccessTokenJti, AccessTokenExpUtc
                  FROM auth.AuthorizationCodes WHERE CodeHash = @Hash AND ConsumedAtUtc IS NOT NULL;
            """);
        cmd.Parameters.Add(Sql.Binary32("@Hash", x.CodeHash));
        cmd.Parameters.Add(Sql.VarChar("@ClientId", x.ClientId, 100));
        cmd.Parameters.Add(Sql.NVarChar("@RedirectUri", x.RedirectUri, 2000));
        cmd.Parameters.Add(Sql.VarChar("@Challenge", x.CodeChallenge, 128));
        cmd.Parameters.Add(Sql.DateTime2("@Now", x.Now));
        cmd.Parameters.Add(Sql.Guid("@FamilyId", x.RefreshFamilyId));
        cmd.Parameters.Add(Sql.VarChar("@Jti", x.AccessTokenJti, 64));
        cmd.Parameters.Add(Sql.DateTime2("@AtExp", x.AccessTokenExpiresAt));

        await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (await r.ReadAsync(ct).ConfigureAwait(false))
        {
            return new CodeRedemptionResult(CodeRedemptionStatus.Redeemed, new AuthorizationCodeRecord
            {
                Id = r.GetInt64(0),
                CodeHash = x.CodeHash,
                ClientId = x.ClientId,
                UserId = r.GetString(1),
                RedirectUri = x.RedirectUri,
                Scopes = r.GetString(2),
                CodeChallenge = x.CodeChallenge,
                Nonce = r.StringOrNull(3),
                AuthTime = r.Utc(4),
                CreatedAt = r.Utc(5),
                ExpiresAt = r.Utc(6),
                ConsumedAt = x.Now,
            });
        }

        if (await r.NextResultAsync(ct).ConfigureAwait(false) && await r.ReadAsync(ct).ConfigureAwait(false))
        {
            return new CodeRedemptionResult(CodeRedemptionStatus.Replayed, new AuthorizationCodeRecord
            {
                CodeHash = x.CodeHash,
                ClientId = x.ClientId,
                UserId = "",
                RedirectUri = "",
                Scopes = "",
                CodeChallenge = "",
                AuthTime = default,
                CreatedAt = default,
                ExpiresAt = default,
                ConsumedAt = r.UtcOrNull(0),
                RefreshFamilyId = r.IsDBNull(1) ? null : r.GetGuid(1),
                AccessTokenJti = r.StringOrNull(2),
                AccessTokenExpiresAt = r.UtcOrNull(3),
            });
        }

        return new CodeRedemptionResult(CodeRedemptionStatus.Invalid, null);
    }

    public async Task CreateRefreshTokenAsync(RefreshTokenRecord token, CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = SqlConnectionFactory.Command(connection, InsertRefreshSql);
        AddRefreshParameters(cmd, token);
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private const string InsertRefreshSql = """
        INSERT INTO auth.RefreshTokens (TokenHash, FamilyId, ClientId, UserId, Scopes, AuthTimeUtc, CreatedAtUtc, ExpiresAtUtc)
        VALUES (@Hash, @FamilyId, @ClientId, @UserId, @Scopes, @AuthTime, @CreatedAt, @ExpiresAt);
        """;

    private static void AddRefreshParameters(SqlCommand cmd, RefreshTokenRecord t)
    {
        cmd.Parameters.Add(Sql.Binary32("@Hash", t.TokenHash));
        cmd.Parameters.Add(Sql.Guid("@FamilyId", t.FamilyId));
        cmd.Parameters.Add(Sql.VarChar("@ClientId", t.ClientId, 100));
        cmd.Parameters.Add(Sql.NVarChar("@UserId", t.UserId, 128));
        cmd.Parameters.Add(Sql.VarChar("@Scopes", t.Scopes, 2000));
        cmd.Parameters.Add(Sql.DateTime2("@AuthTime", t.AuthTime));
        cmd.Parameters.Add(Sql.DateTime2("@CreatedAt", t.CreatedAt));
        cmd.Parameters.Add(Sql.DateTime2("@ExpiresAt", t.ExpiresAt));
    }

    public async Task<RefreshTokenRecord?> FindRefreshTokenAsync(byte[] tokenHash, CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = SqlConnectionFactory.Command(connection, """
            SELECT Id, FamilyId, ClientId, UserId, Scopes, AuthTimeUtc, CreatedAtUtc, ExpiresAtUtc, ConsumedAtUtc, RevokedAtUtc
            FROM auth.RefreshTokens WHERE TokenHash = @Hash;
            """);
        cmd.Parameters.Add(Sql.Binary32("@Hash", tokenHash));
        await using var r = await cmd.ExecuteReaderAsync(System.Data.CommandBehavior.SingleRow, ct).ConfigureAwait(false);
        if (!await r.ReadAsync(ct).ConfigureAwait(false)) return null;
        return new RefreshTokenRecord
        {
            Id = r.GetInt64(0),
            TokenHash = tokenHash,
            FamilyId = r.GetGuid(1),
            ClientId = r.GetString(2),
            UserId = r.GetString(3),
            Scopes = r.GetString(4),
            AuthTime = r.Utc(5),
            CreatedAt = r.Utc(6),
            ExpiresAt = r.Utc(7),
            ConsumedAt = r.UtcOrNull(8),
            RevokedAt = r.UtcOrNull(9),
        };
    }

    public async Task<bool> RotateRefreshTokenAsync(long currentId, RefreshTokenRecord replacement, DateTimeOffset now, CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = SqlConnectionFactory.Command(connection, $"""
            SET XACT_ABORT ON;
            BEGIN TRANSACTION;
            UPDATE auth.RefreshTokens SET ConsumedAtUtc = @Now
             WHERE Id = @CurrentId AND ConsumedAtUtc IS NULL AND RevokedAtUtc IS NULL;
            IF @@ROWCOUNT = 1
            BEGIN
                {InsertRefreshSql}
                COMMIT TRANSACTION;
                SELECT CAST(1 AS bit);
            END
            ELSE
            BEGIN
                ROLLBACK TRANSACTION;
                SELECT CAST(0 AS bit);
            END
            """);
        cmd.Parameters.Add(Sql.BigInt("@CurrentId", currentId));
        cmd.Parameters.Add(Sql.DateTime2("@Now", now));
        AddRefreshParameters(cmd, replacement);
        return await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) is true;
    }

    public async Task<int> RevokeRefreshTokenFamilyAsync(Guid familyId, DateTimeOffset now, CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = SqlConnectionFactory.Command(connection,
            "UPDATE auth.RefreshTokens SET RevokedAtUtc = @Now WHERE FamilyId = @FamilyId AND RevokedAtUtc IS NULL;");
        cmd.Parameters.Add(Sql.Guid("@FamilyId", familyId));
        cmd.Parameters.Add(Sql.DateTime2("@Now", now));
        return await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    public async Task RevokeAccessTokenAsync(string jti, DateTimeOffset expiresAt, CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = SqlConnectionFactory.Command(connection, """
            IF NOT EXISTS (SELECT 1 FROM auth.RevokedAccessTokens WHERE Jti = @Jti)
                INSERT INTO auth.RevokedAccessTokens (Jti, ExpiresAtUtc) VALUES (@Jti, @ExpiresAt);
            """);
        cmd.Parameters.Add(Sql.VarChar("@Jti", jti, 64));
        cmd.Parameters.Add(Sql.DateTime2("@ExpiresAt", expiresAt));
        try
        {
            await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
        catch (SqlException ex) when (Sql.IsDuplicateKey(ex))
        {
            // Concurrent revocation of the same token: already revoked.
        }
    }

    public async Task<bool> IsAccessTokenRevokedAsync(string jti, CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = SqlConnectionFactory.Command(connection, "SELECT CAST(1 AS bit) FROM auth.RevokedAccessTokens WHERE Jti = @Jti;");
        cmd.Parameters.Add(Sql.VarChar("@Jti", jti, 64));
        return await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) is true;
    }

    public async Task<bool> TryRegisterClientAssertionAsync(string clientId, string jti, DateTimeOffset expiresAt, CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = SqlConnectionFactory.Command(connection,
            "INSERT INTO auth.ClientAssertionJtis (ClientId, Jti, ExpiresAtUtc) VALUES (@ClientId, @Jti, @ExpiresAt);");
        cmd.Parameters.Add(Sql.VarChar("@ClientId", clientId, 100));
        cmd.Parameters.Add(Sql.VarChar("@Jti", jti, 256));
        cmd.Parameters.Add(Sql.DateTime2("@ExpiresAt", expiresAt));
        try
        {
            await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            return true;
        }
        catch (SqlException ex) when (Sql.IsDuplicateKey(ex))
        {
            return false;
        }
    }

    public async Task<int> CleanupAsync(DateTimeOffset now, int batchSize, CancellationToken ct)
    {
        // Consumed codes are kept one day after expiry so replays can still be detected and investigated.
        var codeCutoff = now.AddDays(-1);
        var total = 0;
        (string Sql, DateTimeOffset Cutoff)[] statements =
        [
            ("DELETE TOP (@Batch) FROM auth.AuthorizationCodes WHERE ExpiresAtUtc < @Cutoff;", codeCutoff),
            ("DELETE TOP (@Batch) FROM auth.RefreshTokens WHERE ExpiresAtUtc < @Cutoff;", now),
            ("DELETE TOP (@Batch) FROM auth.RevokedAccessTokens WHERE ExpiresAtUtc < @Cutoff;", now),
            ("DELETE TOP (@Batch) FROM auth.ClientAssertionJtis WHERE ExpiresAtUtc < @Cutoff;", now),
        ];

        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        foreach (var (sql, cutoff) in statements)
        {
            int deleted;
            do
            {
                await using var cmd = SqlConnectionFactory.Command(connection, sql);
                cmd.Parameters.Add(Sql.Int("@Batch", batchSize));
                cmd.Parameters.Add(Sql.DateTime2("@Cutoff", cutoff));
                deleted = await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
                total += deleted;
            }
            while (deleted == batchSize && !ct.IsCancellationRequested);
        }
        return total;
    }
}
