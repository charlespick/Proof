using System.Net;
using System.Reflection;
using Proof.Metadata;

const string Help = """
    proof-metadata [--port <port>]
                          Serve instance metadata to this VM on http://127.0.0.1:<port>, default 8169, from its
                          Hyper-V host. As a Windows or systemd service, or in the console. Only this VM can reach it.
    proof-metadata --version
                          Print the version.
    """;

var port = MetadataApi.DefaultPort;
switch (args)
{
    case []:
        break;
    case ["--version"]:
        Console.WriteLine(typeof(MetadataApi).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion);
        return 0;
    case ["--port", var text] when ushort.TryParse(text, out var parsed) && parsed != 0:
        port = parsed;
        break;
    default:
        Console.Error.WriteLine(Help);
        return 2;
}

// The empty builder reads no configuration, so no environment variable or file can widen the address below. It also
// leaves out Kestrel's configuration loader, which fails with a TypeLoadException at start once trimmed.
var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions { ContentRootPath = AppContext.BaseDirectory });
builder.Logging.AddSimpleConsole();
// Not every request: a boot reads dozens of paths.
builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.WebHost.UseKestrelCore();
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Listen(IPAddress.Loopback, port);
    // Nothing reads a body, and headers are all a caller needs.
    options.Limits.MaxRequestBodySize = 64 * 1024;
    options.Limits.MaxRequestHeadersTotalSize = 16 * 1024;
    options.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(30);
});
builder.Services.AddWindowsService(options => options.ServiceName = "proof-metadata");
builder.Services.AddSystemd();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<IHostChannel, HyperVSocketChannel>();
builder.Services.AddSingleton<MetadataApi>();

var app = builder.Build();
var api = app.Services.GetRequiredService<MetadataApi>();
app.Run(api.HandleAsync);
await app.RunAsync();
return 0;
