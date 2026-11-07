using System.Data;
using System.Globalization;
using Microsoft.Data.SqlClient;

namespace AddAccion.Auth.Persistence.SqlServer;

/// <summary>Thin ADO.NET helpers: explicit parameter types/sizes (stable cached plans, no implicit conversions).</summary>
public sealed class SqlConnectionFactory
{
    private const int CommandTimeoutSeconds = 10;
    private readonly string _connectionString;

    public SqlConnectionFactory(string connectionString)
    {
        var builder = new SqlConnectionStringBuilder(connectionString);
        if (string.IsNullOrEmpty(builder.ApplicationName) || builder.ApplicationName == "Core Microsoft SqlClient Data Provider")
            builder.ApplicationName = "AddAccion.Auth";
        _connectionString = builder.ConnectionString;
    }

    public async Task<SqlConnection> OpenAsync(CancellationToken ct)
    {
        var connection = new SqlConnection(_connectionString);
        try
        {
            await connection.OpenAsync(ct).ConfigureAwait(false);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public static SqlCommand Command(SqlConnection connection, string sql, SqlTransaction? transaction = null) =>
        new(sql, connection, transaction) { CommandTimeout = CommandTimeoutSeconds, CommandType = CommandType.Text };
}

internal static class Sql
{
    public const int UniqueViolation = 2627;
    public const int UniqueIndexViolation = 2601;

    public static bool IsDuplicateKey(SqlException ex) => ex.Number is UniqueViolation or UniqueIndexViolation;

    public static SqlParameter VarChar(string name, string? value, int size) =>
        new(name, SqlDbType.VarChar, size) { Value = (object?)value ?? DBNull.Value };

    public static SqlParameter NVarChar(string name, string? value, int size) =>
        new(name, SqlDbType.NVarChar, size) { Value = (object?)value ?? DBNull.Value };

    public static SqlParameter Text(string name, string? value, int size, bool varchar) =>
        varchar ? VarChar(name, value, size) : NVarChar(name, value, size);

    public static SqlParameter NVarCharMax(string name, string? value) =>
        new(name, SqlDbType.NVarChar, -1) { Value = (object?)value ?? DBNull.Value };

    public static SqlParameter Binary32(string name, byte[] value) =>
        new(name, SqlDbType.Binary, 32) { Value = value };

    public static SqlParameter Int(string name, int value) => new(name, SqlDbType.Int) { Value = value };

    public static SqlParameter BigInt(string name, long value) => new(name, SqlDbType.BigInt) { Value = value };

    public static SqlParameter TinyInt(string name, byte value) => new(name, SqlDbType.TinyInt) { Value = value };

    public static SqlParameter Bit(string name, bool value) => new(name, SqlDbType.Bit) { Value = value };

    public static SqlParameter Guid(string name, Guid? value) =>
        new(name, SqlDbType.UniqueIdentifier) { Value = (object?)value ?? DBNull.Value };

    public static SqlParameter DateTime2(string name, DateTimeOffset? value) =>
        new(name, SqlDbType.DateTime2) { Scale = 3, Value = value.HasValue ? value.Value.UtcDateTime : DBNull.Value };

    public static DateTimeOffset Utc(this SqlDataReader r, int i) =>
        new(DateTime.SpecifyKind(r.GetDateTime(i), DateTimeKind.Utc), TimeSpan.Zero);

    public static DateTimeOffset? UtcOrNull(this SqlDataReader r, int i) =>
        r.IsDBNull(i) ? null : r.Utc(i);

    public static string? StringOrNull(this SqlDataReader r, int i) =>
        r.IsDBNull(i) ? null : r.GetString(i);

    /// <summary>Lenient read for columns of the customer-defined user views (int/guid/varchar all map to string).</summary>
    public static string? AnyAsString(this SqlDataReader r, int i) =>
        r.IsDBNull(i) ? null : Convert.ToString(r.GetValue(i), CultureInfo.InvariantCulture);

    /// <summary>Lenient boolean (bit/int/tinyint) for the user views.</summary>
    public static bool AnyAsBool(this SqlDataReader r, int i) =>
        !r.IsDBNull(i) && Convert.ToBoolean(r.GetValue(i), CultureInfo.InvariantCulture);
}
