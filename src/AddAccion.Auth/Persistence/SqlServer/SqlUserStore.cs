using AddAccion.Auth.Configuration;
using AddAccion.Auth.Domain;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;

namespace AddAccion.Auth.Persistence.SqlServer;

/// <summary>Reads users only through the contract views auth.vw_Users / auth.vw_UserRoles.</summary>
public sealed class SqlUserStore(SqlConnectionFactory db, IOptions<AuthServerOptions> options) : IUserStore
{
    private readonly bool _varchar = options.Value.Users.UseVarcharParameters;

    private const string UserColumns = """
        u.UserId, u.LoginName, u.Email, u.EmailVerified, u.DisplayName, u.GivenName, u.FamilyName, u.PasswordHash, u.IsActive, s.LockoutEndUtc
        """;

    private const string FindByLoginSql = $"""
        SELECT TOP (2) {UserColumns}
        FROM auth.vw_Users AS u
        LEFT JOIN auth.UserLoginState AS s ON s.UserId = u.UserId COLLATE DATABASE_DEFAULT
        WHERE u.LoginName = @Login;
        """;

    private const string FindByIdSql = $"""
        SELECT TOP (2) {UserColumns}
        FROM auth.vw_Users AS u
        LEFT JOIN auth.UserLoginState AS s ON s.UserId = u.UserId COLLATE DATABASE_DEFAULT
        WHERE u.UserId = @UserId;
        SELECT RoleName FROM auth.vw_UserRoles WHERE UserId = @UserId;
        """;

    public async Task<UserAccount?> FindByLoginAsync(string loginName, CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = SqlConnectionFactory.Command(connection, FindByLoginSql);
        cmd.Parameters.Add(Sql.Text("@Login", loginName, 256, _varchar));
        await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return await ReadSingleUserAsync(r, ct).ConfigureAwait(false);
    }

    public async Task<UserAccount?> FindByIdAsync(string userId, CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = SqlConnectionFactory.Command(connection, FindByIdSql);
        cmd.Parameters.Add(Sql.Text("@UserId", userId, 128, _varchar));
        await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        var user = await ReadSingleUserAsync(r, ct).ConfigureAwait(false);
        if (user is null) return null;

        var roles = new List<string>();
        await r.NextResultAsync(ct).ConfigureAwait(false);
        while (await r.ReadAsync(ct).ConfigureAwait(false))
        {
            var role = r.AnyAsString(0);
            if (!string.IsNullOrEmpty(role)) roles.Add(role);
        }
        return user with { Roles = roles };
    }

    private static async Task<UserAccount?> ReadSingleUserAsync(SqlDataReader r, CancellationToken ct)
    {
        if (!await r.ReadAsync(ct).ConfigureAwait(false)) return null;
        var user = new UserAccount
        {
            UserId = r.AnyAsString(0) ?? "",
            LoginName = r.AnyAsString(1) ?? "",
            Email = r.AnyAsString(2),
            EmailVerified = r.AnyAsBool(3),
            DisplayName = r.AnyAsString(4),
            GivenName = r.AnyAsString(5),
            FamilyName = r.AnyAsString(6),
            PasswordHash = r.AnyAsString(7),
            IsActive = r.AnyAsBool(8),
            LockoutEnd = r.UtcOrNull(9),
        };
        // An ambiguous login (duplicate LoginName in the view) is treated as "not found": never guess the account.
        if (await r.ReadAsync(ct).ConfigureAwait(false)) return null;
        return string.IsNullOrEmpty(user.UserId) ? null : user;
    }

    public async Task<DateTimeOffset?> RecordFailedLoginAsync(string userId, DateTimeOffset now, int maxAttempts, TimeSpan lockout, CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = SqlConnectionFactory.Command(connection, """
            MERGE auth.UserLoginState WITH (HOLDLOCK) AS t
            USING (SELECT @UserId AS UserId) AS s ON t.UserId = s.UserId
            WHEN MATCHED THEN UPDATE SET
                t.FailedCount = CASE WHEN t.LockoutEndUtc IS NOT NULL AND t.LockoutEndUtc <= @Now THEN 1 ELSE t.FailedCount + 1 END,
                t.LockoutEndUtc = CASE
                    WHEN (CASE WHEN t.LockoutEndUtc IS NOT NULL AND t.LockoutEndUtc <= @Now THEN 1 ELSE t.FailedCount + 1 END) >= @Max THEN @LockoutEnd
                    ELSE NULL END,
                t.LastFailureUtc = @Now
            WHEN NOT MATCHED THEN
                INSERT (UserId, FailedCount, LockoutEndUtc, LastFailureUtc)
                VALUES (@UserId, 1, CASE WHEN 1 >= @Max THEN @LockoutEnd ELSE NULL END, @Now)
            OUTPUT inserted.LockoutEndUtc;
            """);
        cmd.Parameters.Add(Sql.NVarChar("@UserId", userId, 128));
        cmd.Parameters.Add(Sql.DateTime2("@Now", now));
        cmd.Parameters.Add(Sql.Int("@Max", maxAttempts));
        cmd.Parameters.Add(Sql.DateTime2("@LockoutEnd", now + lockout));
        var result = await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
        return result is DateTime dt ? new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc), TimeSpan.Zero) : null;
    }

    public async Task RecordSuccessfulLoginAsync(string userId, DateTimeOffset now, CancellationToken ct)
    {
        await using var connection = await db.OpenAsync(ct).ConfigureAwait(false);
        // Only touches users that already have a row (i.e. had failures): no write per login otherwise.
        await using var cmd = SqlConnectionFactory.Command(connection, """
            UPDATE auth.UserLoginState SET FailedCount = 0, LockoutEndUtc = NULL, LastSuccessUtc = @Now
            WHERE UserId = @UserId AND (FailedCount <> 0 OR LockoutEndUtc IS NOT NULL);
            """);
        cmd.Parameters.Add(Sql.NVarChar("@UserId", userId, 128));
        cmd.Parameters.Add(Sql.DateTime2("@Now", now));
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }
}
