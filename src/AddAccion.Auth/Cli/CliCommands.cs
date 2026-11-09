using System.Text.Json;
using System.Text.RegularExpressions;
using AddAccion.Auth.Crypto;
using AddAccion.Auth.Endpoints;
using AddAccion.Auth.Hosting;
using AddAccion.Auth.Persistence;
using AddAccion.Auth.Persistence.SqlServer;
using Microsoft.Data.SqlClient;

namespace AddAccion.Auth.Cli;

/// <summary>
/// Operational commands shipped in the same binary/container image:
///   migrate | generate-key | add-scope | create-client
/// Configuration (connection strings) comes from appsettings, environment variables or --ConnectionStrings:AuthDb=...
/// </summary>
public static partial class CliCommands
{
    private static readonly string[] Commands = ["migrate", "generate-key", "add-scope", "create-client", "help"];

    public static bool IsCommand(string arg) => Commands.Contains(arg, StringComparer.Ordinal);

    public static async Task<int> RunAsync(string[] args)
    {
        var command = args[0];
        var options = ParseOptions(args.AsSpan(1), out var configArgs);
        var configuration = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: true)
            .AddEnvironmentVariables()
            .AddCommandLine(configArgs)
            .Build();

        try
        {
            return command switch
            {
                "migrate" => await MigrateAsync(MigrationConnectionString(configuration)).ConfigureAwait(false),
                "generate-key" => GenerateKey(options),
                "add-scope" => await AddScopeAsync(RuntimeConnectionString(configuration), options).ConfigureAwait(false),
                "create-client" => await CreateClientAsync(RuntimeConnectionString(configuration), options).ConfigureAwait(false),
                _ => Help(),
            };
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or SqlException or IOException)
        {
            await Console.Error.WriteLineAsync("error: " + ex.Message).ConfigureAwait(false);
            return 1;
        }
    }

    private static int Help()
    {
        Console.WriteLine("""
            AddAccion.Auth commands:
              migrate                                    apply db/migrations (ConnectionStrings:AuthDbMigrations or AuthDb)
              generate-key --type rsa|ec --out <file>    write a new PKCS#8 PEM signing key
              generate-key --type rsa|ec --base64        print it as single-line base64 (for Auth__SigningKeys__Inline__N)
              add-scope --name <scope> --audience <aud> [--description <text>]
              create-client --id <id> --name <name> --grants <g1,g2> --scopes <s1,s2>
                            [--type confidential|public] [--auth client_secret_basic|client_secret_post|private_key_jwt|none]
                            [--redirect-uris <u1,u2>] [--jwks-file <file>] [--introspect] [--secret-days <n>]
            """);
        return 0;
    }

    private static Dictionary<string, string> ParseOptions(ReadOnlySpan<string> args, out string[] configArgs)
    {
        var options = new Dictionary<string, string>(StringComparer.Ordinal);
        var config = new List<string>();
        for (var i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (a.StartsWith("--", StringComparison.Ordinal) && a.Contains(':', StringComparison.Ordinal))
            {
                config.Add(a); // configuration override, e.g. --ConnectionStrings:AuthDb=...
                continue;
            }
            if (!a.StartsWith("--", StringComparison.Ordinal)) throw new ArgumentException($"Unexpected argument '{a}'.");
            var key = a[2..];
            if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal)) options[key] = args[++i];
            else options[key] = "true";
        }
        configArgs = [.. config];
        return options;
    }

    private static string Required(Dictionary<string, string> o, string key) =>
        o.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v) ? v : throw new ArgumentException($"--{key} is required.");

    private static string RuntimeConnectionString(IConfiguration c) =>
        c.GetConnectionString(AuthServer.ConnectionStringName) ?? throw new InvalidOperationException("ConnectionStrings:AuthDb is not configured.");

    private static string MigrationConnectionString(IConfiguration c) =>
        c.GetConnectionString("AuthDbMigrations") ?? RuntimeConnectionString(c);

    [GeneratedRegex(@"^\s*GO\s*;?\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BatchSeparator();

    public static async Task<int> MigrateAsync(string connectionString)
    {
        var factory = new SqlConnectionFactory(connectionString);
        var assembly = typeof(CliCommands).Assembly;
        var scripts = assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith("migrations/", StringComparison.Ordinal) && n.EndsWith(".sql", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .ToArray();

        await using var connection = await factory.OpenAsync(CancellationToken.None).ConfigureAwait(false);
        foreach (var name in scripts)
        {
            var fileName = name["migrations/".Length..];
            var version = int.Parse(fileName.AsSpan(0, 4), System.Globalization.CultureInfo.InvariantCulture);
            if (await IsAppliedAsync(connection, version).ConfigureAwait(false))
            {
                Console.WriteLine($"skip   {fileName}");
                continue;
            }

            await using var stream = assembly.GetManifestResourceStream(name)!;
            using var reader = new StreamReader(stream);
            var sql = await reader.ReadToEndAsync().ConfigureAwait(false);
            foreach (var batch in BatchSeparator().Split(sql))
            {
                if (string.IsNullOrWhiteSpace(batch)) continue;
                await using var cmd = new SqlCommand(batch, connection) { CommandTimeout = 300 };
                await cmd.ExecuteNonQueryAsync().ConfigureAwait(false);
            }
            Console.WriteLine($"apply  {fileName}");
        }
        return 0;
    }

    private static async Task<bool> IsAppliedAsync(SqlConnection connection, int version)
    {
        // Two statements: a reference to a missing table fails at compile time even inside CASE.
        await using (var exists = new SqlCommand("SELECT OBJECT_ID(N'auth.SchemaVersions', N'U');", connection))
        {
            if (await exists.ExecuteScalarAsync().ConfigureAwait(false) is null or DBNull) return false;
        }
        await using var cmd = new SqlCommand("SELECT COUNT(*) FROM auth.SchemaVersions WHERE Version = @v;", connection);
        cmd.Parameters.Add(Sql.Int("@v", version));
        return Convert.ToInt32(await cmd.ExecuteScalarAsync().ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture) > 0;
    }

    private static int GenerateKey(Dictionary<string, string> o)
    {
        var type = o.GetValueOrDefault("type", "rsa");
        if (o.ContainsKey("base64"))
        {
            // For platforms where keys live in environment variables (Auth__SigningKeys__Inline__N).
            var generated = SigningKeyStore.GeneratePem(type);
            var info = SigningKeyStore.FromPem(generated, "generated");
            Console.WriteLine(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(generated)));
            Console.Error.WriteLine($"kid={info.KeyId} alg={info.Algorithm} (stdout holds the PRIVATE key: paste it into the secret store, do not keep it)");
            return 0;
        }
        var output = Required(o, "out");
        if (File.Exists(output)) throw new IOException($"'{output}' already exists; refusing to overwrite a key.");
        var pem = SigningKeyStore.GeneratePem(type);
        File.WriteAllText(output, pem);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(output, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var key = SigningKeyStore.FromPem(pem, output);
        Console.WriteLine($"written {output} kid={key.KeyId} alg={key.Algorithm}");
        return 0;
    }

    private static async Task<int> AddScopeAsync(string connectionString, Dictionary<string, string> o)
    {
        var name = Required(o, "name");
        var audience = Required(o, "audience");
        if (!Protocol.ScopeParser.TryParse(name, out var parsed) || parsed.Count != 1)
            throw new ArgumentException("Invalid scope name.");
        var factory = new SqlConnectionFactory(connectionString);
        await using var connection = await factory.OpenAsync(CancellationToken.None).ConfigureAwait(false);
        await using var cmd = new SqlCommand("""
            IF NOT EXISTS (SELECT 1 FROM auth.Scopes WHERE Name = @Name)
                INSERT INTO auth.Scopes (Name, Audience, Description) VALUES (@Name, @Audience, @Description);
            ELSE
                UPDATE auth.Scopes SET Audience = @Audience, Description = @Description WHERE Name = @Name;
            """, connection);
        cmd.Parameters.Add(Sql.VarChar("@Name", name, 200));
        cmd.Parameters.Add(Sql.VarChar("@Audience", audience, 500));
        cmd.Parameters.Add(Sql.NVarChar("@Description", o.GetValueOrDefault("description"), 500));
        await cmd.ExecuteNonQueryAsync().ConfigureAwait(false);
        Console.WriteLine($"scope {name} -> aud {audience}");
        return 0;
    }

    private static async Task<int> CreateClientAsync(string connectionString, Dictionary<string, string> o)
    {
        static string[] List(Dictionary<string, string> o, string key) =>
            o.TryGetValue(key, out var v) ? v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) : [];

        JsonElement? jwks = null;
        if (o.TryGetValue("jwks-file", out var jwksFile))
        {
            using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(jwksFile).ConfigureAwait(false));
            jwks = doc.RootElement.Clone();
        }

        var request = new CreateClientRequest
        {
            ClientId = Required(o, "id"),
            ClientName = Required(o, "name"),
            ClientType = o.GetValueOrDefault("type", "confidential"),
            TokenEndpointAuthMethod = o.GetValueOrDefault("auth"),
            GrantTypes = List(o, "grants"),
            Scopes = List(o, "scopes"),
            RedirectUris = List(o, "redirect-uris"),
            Jwks = jwks,
            CanIntrospect = o.ContainsKey("introspect"),
            SecretLifetimeDays = o.TryGetValue("secret-days", out var d) ? int.Parse(d, System.Globalization.CultureInfo.InvariantCulture) : null,
        };

        var factory = new SqlConnectionFactory(connectionString);
        var scopes = await new SqlScopeStore(factory).GetAllAsync(CancellationToken.None).ConfigureAwait(false);
        var (client, secret, error) = ClientRegistration.Build(request, new ScopeSnapshot(scopes, DateTimeOffset.MaxValue), DateTimeOffset.UtcNow);
        if (client is null) throw new ArgumentException(error);
        var store = new SqlClientStore(factory);
        if (!await store.CreateAsync(client, CancellationToken.None).ConfigureAwait(false))
            throw new InvalidOperationException($"client_id '{client.ClientId}' already exists.");
        var created = await store.FindAsync(client.ClientId, CancellationToken.None).ConfigureAwait(false) ?? client;

        Console.WriteLine(JsonSerializer.Serialize(ClientView.From(created, secret), AuthJsonContext.Default.ClientView));
        if (secret is not null) await Console.Error.WriteLineAsync("Store client_secret now in a secret manager: it cannot be recovered.").ConfigureAwait(false);
        return 0;
    }
}
