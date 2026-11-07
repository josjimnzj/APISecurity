using System.Security.Cryptography;
using System.Text.RegularExpressions;
using AddAccion.Auth.Cli;
using AddAccion.Auth.Crypto;
using AddAccion.Auth.Domain;
using AddAccion.Auth.Persistence;
using AddAccion.Auth.Persistence.SqlServer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;

namespace AddAccion.Auth.Tests.Infrastructure;

public sealed record UserSeed(string UserId, string LoginName, string Password, string? Email = null, string[]? Roles = null, bool Active = true,
    string? GivenName = "Ana", string? FamilyName = "García");

/// <summary>
/// A running authorization server plus a way to seed data. The protocol tests only talk HTTP, so the same suite
/// runs in-process (in-memory or SQL Server stores) and against an external process (e.g. the Native AOT binary,
/// or a future Go implementation sharing the same database schema).
/// </summary>
public abstract class AuthServerFixture : IAsyncLifetime
{
    public const int MaxFailedAttempts = 3;

    public static readonly string[] ApiScopes = ["erp.read", "erp.write", "crm.read"];

    public static string AudienceOf(string scope) => scope switch
    {
        "erp.read" or "erp.write" => "https://api.addaccion.test/erp",
        "crm.read" => "https://api.addaccion.test/crm",
        "auth.admin" => "urn:addaccion:auth:admin",
        _ => throw new ArgumentOutOfRangeException(nameof(scope)),
    };

    public abstract string Issuer { get; }

    /// <summary>Controllable clock (null when the server runs out of process).</summary>
    public virtual FakeTimeProvider? Clock => null;

    public virtual string? UnavailableReason => null;

    public void SkipIfUnavailable()
    {
        if (UnavailableReason is { } reason) Assert.Skip(reason);
    }

    public abstract HttpClient CreateClient();
    public abstract Task SeedClientAsync(ClientApplication client);
    public abstract Task SeedUserAsync(UserSeed user);
    public abstract Task SetUserActiveAsync(string userId, bool active);

    public virtual ValueTask InitializeAsync() => ValueTask.CompletedTask;

    public virtual ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    public static string HashPassword(string password) => new PasswordHasher<object>().HashPassword(new object(), password);
}

/// <summary>Hosts Program in-process through TestServer with test configuration and signing keys.</summary>
internal sealed class InProcessServer : WebApplicationFactory<Program>
{
    public const string Issuer = "https://localhost";

    private readonly Action<IServiceCollection> _services;
    private readonly Dictionary<string, string> _settings;

    public string KeyDirectory { get; }

    public InProcessServer(Action<IServiceCollection> services, IDictionary<string, string>? extra = null)
    {
        _services = services;
        KeyDirectory = Directory.CreateTempSubdirectory("addaccion-auth-keys-").FullName;
        File.WriteAllText(Path.Combine(KeyDirectory, "rsa.pem"), SigningKeyStore.GeneratePem("rsa"));
        File.WriteAllText(Path.Combine(KeyDirectory, "ec.pem"), SigningKeyStore.GeneratePem("ec"));

        _settings = new Dictionary<string, string>
        {
            ["Auth:Issuer"] = Issuer,
            ["Auth:RequireHttps"] = "true",
            ["Auth:SigningKeys:Path"] = KeyDirectory,
            ["Auth:SigningKeys:ActiveKey"] = "rsa.pem",
            ["Auth:Login:CsrfKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            ["Auth:Login:MaxFailedAttempts"] = AuthServerFixture.MaxFailedAttempts.ToString(),
            ["Auth:Login:LockoutSeconds"] = "300",
            ["Auth:RateLimits:Enabled"] = "false",
            ["Auth:Cleanup:Enabled"] = "false",
            ["Logging:LogLevel:Default"] = "Warning",
        };
        if (extra is not null)
        {
            foreach (var (k, v) in extra) _settings[k] = v;
        }
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        foreach (var (key, value) in _settings) builder.UseSetting(key, value);
        builder.ConfigureTestServices(_services);
    }

    public HttpClient CreateHttpClient() => CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        HandleCookies = false,
        BaseAddress = new Uri(Issuer),
    });

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        try { Directory.Delete(KeyDirectory, recursive: true); } catch (IOException) { }
    }
}

public sealed class InMemoryFixture : AuthServerFixture
{
    private readonly InProcessServer _server;

    public InMemoryDatabase Database { get; } = new();
    public override FakeTimeProvider Clock { get; } = new(DateTimeOffset.UtcNow);
    public override string Issuer => InProcessServer.Issuer;

    public InMemoryFixture()
    {
        Database.AddScope(new ScopeDefinition("auth.admin", AudienceOf("auth.admin"), null, true));
        foreach (var s in ApiScopes) Database.AddScope(new ScopeDefinition(s, AudienceOf(s), null, true));
        _server = new InProcessServer(services =>
        {
            services.RemoveAll<IClientStore>().AddSingleton<IClientStore>(Database);
            services.RemoveAll<IScopeStore>().AddSingleton<IScopeStore>(Database);
            services.RemoveAll<IUserStore>().AddSingleton<IUserStore>(Database);
            services.RemoveAll<IGrantStore>().AddSingleton<IGrantStore>(Database);
            services.RemoveAll<IDatabaseHealth>().AddSingleton<IDatabaseHealth>(Database);
            services.RemoveAll<TimeProvider>().AddSingleton<TimeProvider>(Clock);
        });
    }

    public override HttpClient CreateClient() => _server.CreateHttpClient();

    public override Task SeedClientAsync(ClientApplication client) => Database.CreateAsync(client, default);

    public override Task SeedUserAsync(UserSeed u)
    {
        Database.AddUser(new UserAccount
        {
            UserId = u.UserId,
            LoginName = u.LoginName,
            Email = u.Email,
            EmailVerified = u.Email is not null,
            GivenName = u.GivenName,
            FamilyName = u.FamilyName,
            DisplayName = $"{u.GivenName} {u.FamilyName}".Trim(),
            PasswordHash = HashPassword(u.Password),
            IsActive = u.Active,
            Roles = u.Roles ?? [],
        });
        return Task.CompletedTask;
    }

    public override Task SetUserActiveAsync(string userId, bool active)
    {
        Database.SetUserActive(userId, active);
        return Task.CompletedTask;
    }

    public override async ValueTask DisposeAsync()
    {
        await _server.DisposeAsync();
        await base.DisposeAsync();
    }
}

/// <summary>Seeds the real schema (auth.* tables + example user tables behind the contract views).</summary>
internal static partial class SqlSeeder
{
    [GeneratedRegex(@"^\s*GO\s*;?\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex Go();

    public static async Task PrepareDatabaseAsync(string connectionString)
    {
        await CliCommands.MigrateAsync(connectionString);
        var script = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "sql", "user_views.example.sql"));
        await using var c = new SqlConnection(connectionString);
        await c.OpenAsync();
        foreach (var batch in Go().Split(script).Where(b => !string.IsNullOrWhiteSpace(b)))
        {
            await using var cmd = new SqlCommand(batch, c);
            await cmd.ExecuteNonQueryAsync();
        }
        foreach (var s in AuthServerFixture.ApiScopes)
        {
            await using var cmd = new SqlCommand(
                "IF NOT EXISTS (SELECT 1 FROM auth.Scopes WHERE Name=@n) INSERT INTO auth.Scopes (Name, Audience) VALUES (@n, @a);", c);
            cmd.Parameters.AddWithValue("@n", s);
            cmd.Parameters.AddWithValue("@a", AuthServerFixture.AudienceOf(s));
            await cmd.ExecuteNonQueryAsync();
        }
    }

    public static async Task SeedClientAsync(string cs, ClientApplication client)
    {
        if (!await new SqlClientStore(new SqlConnectionFactory(cs)).CreateAsync(client, default))
            throw new InvalidOperationException("duplicate client " + client.ClientId);
    }

    public static async Task SeedUserAsync(string cs, UserSeed u)
    {
        await using var c = new SqlConnection(cs);
        await c.OpenAsync();
        await using (var cmd = new SqlCommand("""
            INSERT INTO dbo.AppUsers (Id, UserName, Email, EmailConfirmed, FirstName, LastName, PasswordHash, Active)
            VALUES (@id, @login, @email, @verified, @given, @family, @hash, @active);
            """, c))
        {
            cmd.Parameters.AddWithValue("@id", Guid.Parse(u.UserId));
            cmd.Parameters.AddWithValue("@login", u.LoginName);
            cmd.Parameters.AddWithValue("@email", (object?)u.Email ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@verified", u.Email is not null);
            cmd.Parameters.AddWithValue("@given", (object?)u.GivenName ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@family", (object?)u.FamilyName ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@hash", AuthServerFixture.HashPassword(u.Password));
            cmd.Parameters.AddWithValue("@active", u.Active);
            await cmd.ExecuteNonQueryAsync();
        }
        foreach (var role in u.Roles ?? [])
        {
            await using var cmd = new SqlCommand("INSERT INTO dbo.AppUserRoles (UserKey, RoleName) VALUES (@k, @r);", c);
            cmd.Parameters.AddWithValue("@k", u.UserId);
            cmd.Parameters.AddWithValue("@r", role);
            await cmd.ExecuteNonQueryAsync();
        }
    }

    public static async Task SetUserActiveAsync(string cs, string userId, bool active)
    {
        await using var c = new SqlConnection(cs);
        await c.OpenAsync();
        await using var cmd = new SqlCommand("UPDATE dbo.AppUsers SET Active = @a WHERE Id = @id;", c);
        cmd.Parameters.AddWithValue("@a", active);
        cmd.Parameters.AddWithValue("@id", Guid.Parse(userId));
        await cmd.ExecuteNonQueryAsync();
    }
}

/// <summary>In-process server on a throw-away SQL Server database. Enabled by AUTH_TEST_SQL (server connection string, no database).</summary>
public sealed class SqlServerFixture : AuthServerFixture
{
    private readonly string? _serverConnection = Environment.GetEnvironmentVariable("AUTH_TEST_SQL");
    private readonly string _database = "AddAccionAuthTest_" + Guid.NewGuid().ToString("N")[..12];
    private InProcessServer? _server;
    private string _cs = "";

    public override FakeTimeProvider Clock { get; } = new(DateTimeOffset.UtcNow);
    public override string Issuer => InProcessServer.Issuer;
    public override string? UnavailableReason => string.IsNullOrEmpty(_serverConnection) ? "AUTH_TEST_SQL not set" : null;

    public override async ValueTask InitializeAsync()
    {
        if (UnavailableReason is not null) return;
        await using (var c = new SqlConnection(_serverConnection))
        {
            await c.OpenAsync();
            await using var cmd = new SqlCommand($"CREATE DATABASE [{_database}];", c);
            await cmd.ExecuteNonQueryAsync();
        }
        _cs = new SqlConnectionStringBuilder(_serverConnection) { InitialCatalog = _database }.ConnectionString;
        await SqlSeeder.PrepareDatabaseAsync(_cs);
        _server = new InProcessServer(
            services => services.RemoveAll<TimeProvider>().AddSingleton<TimeProvider>(Clock),
            new Dictionary<string, string> { ["ConnectionStrings:AuthDb"] = _cs });
    }

    public override HttpClient CreateClient() => _server!.CreateHttpClient();
    public override Task SeedClientAsync(ClientApplication client) => SqlSeeder.SeedClientAsync(_cs, client);
    public override Task SeedUserAsync(UserSeed user) => SqlSeeder.SeedUserAsync(_cs, user);
    public override Task SetUserActiveAsync(string userId, bool active) => SqlSeeder.SetUserActiveAsync(_cs, userId, active);

    public override async ValueTask DisposeAsync()
    {
        if (_server is not null) await _server.DisposeAsync();
        if (UnavailableReason is null)
        {
            SqlConnection.ClearAllPools();
            await using var c = new SqlConnection(_serverConnection);
            await c.OpenAsync();
            await using var cmd = new SqlCommand(
                $"IF DB_ID('{_database}') IS NOT NULL BEGIN ALTER DATABASE [{_database}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{_database}]; END", c);
            await cmd.ExecuteNonQueryAsync();
        }
        await base.DisposeAsync();
    }
}

/// <summary>
/// Black-box run against an already running server (e.g. the Native AOT container or a Go port).
/// AUTH_TEST_BASE_URL = server URL; AUTH_TEST_EXTERNAL_DB = connection string of the database it uses.
/// The server must run with Auth:Login:MaxFailedAttempts=3 and rate limiting disabled.
/// </summary>
public sealed class ExternalFixture : AuthServerFixture
{
    private readonly string? _baseUrl = Environment.GetEnvironmentVariable("AUTH_TEST_BASE_URL");
    private readonly string? _cs = Environment.GetEnvironmentVariable("AUTH_TEST_EXTERNAL_DB");
    private string _issuer = "";

    public override string Issuer => _issuer;
    public override string? UnavailableReason =>
        string.IsNullOrEmpty(_baseUrl) || string.IsNullOrEmpty(_cs) ? "AUTH_TEST_BASE_URL / AUTH_TEST_EXTERNAL_DB not set" : null;

    public override async ValueTask InitializeAsync()
    {
        if (UnavailableReason is not null) return;
        await SqlSeeder.PrepareDatabaseAsync(_cs!);
        using var http = CreateClient();
        using var doc = System.Text.Json.JsonDocument.Parse(await http.GetStringAsync("/.well-known/openid-configuration"));
        _issuer = doc.RootElement.GetProperty("issuer").GetString()!;
    }

    public override HttpClient CreateClient() =>
        new(new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false }) { BaseAddress = new Uri(_baseUrl!) };

    public override Task SeedClientAsync(ClientApplication client) => SqlSeeder.SeedClientAsync(_cs!, client);
    public override Task SeedUserAsync(UserSeed user) => SqlSeeder.SeedUserAsync(_cs!, user);
    public override Task SetUserActiveAsync(string userId, bool active) => SqlSeeder.SetUserActiveAsync(_cs!, userId, active);
}
