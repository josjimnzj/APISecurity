using AddAccion.Auth.Cli;
using AddAccion.Auth.Hosting;

if (args.Length > 0 && CliCommands.IsCommand(args[0]))
{
    return await CliCommands.RunAsync(args);
}

var app = AuthServer.Build(args);
await app.RunAsync();
return 0;

/// <summary>Entry point marker for WebApplicationFactory in tests.</summary>
public partial class Program;
