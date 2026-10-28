using System.Reflection;
using Proof.Client;
using Proof.Shared;

const string Help = """
    proof token --audience <aud> [--out <path>] [--wait <seconds>] [--config <path>]
                          Trade this VM's host token for a JWT for <aud>. Prints the JWT, or with --out writes it
                          to <path> in one rename, for SDKs that read a token file. --wait waits up to that long
                          for the host to write an unexpired host token, for use early in boot.
    proof status [--config <path>]
                          Show the host token (without printing it), what it says, and anything that would stop
                          an exchange.
    proof --version       Print the version.

    Settings are read from /etc/proof/config.json on Linux and %ProgramData%\Proof\config.json on Windows:
      { "IssuerUrl": "https://id.example", "TokenEndpoint": "https://...", "CaBundlePath": "ca.pem" }
    Only IssuerUrl is required. TokenEndpoint defaults to IssuerUrl + /token. With CaBundlePath, the issuer's
    certificate must chain to a CA in that PEM file instead of the system store.

    Exit codes: 0 success, 1 failure, 2 usage, 3 no host token yet (retry later).
    """;

using var cancel = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cancel.Cancel();
};

try
{
    return args switch
    {
        ["token", .. var rest] => await TokenAsync(rest),
        ["status", .. var rest] => Status(rest),
        ["--version"] => PrintVersion(),
        _ => Usage(),
    };
}
catch (Exception ex) when (ex is ClientConfigException or KvpUnavailableException or PlatformNotSupportedException)
{
    Console.Error.WriteLine($"proof: {ex.Message}");
    return ExitCodes.Failed;
}
catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
{
    // Writing --out.
    Console.Error.WriteLine($"proof: {ex.Message}");
    return ExitCodes.Failed;
}
catch (OperationCanceledException) when (cancel.IsCancellationRequested)
{
    return 130;
}

async Task<int> TokenAsync(string[] rest)
{
    if (!TryParse(rest, ["--audience", "--out", "--wait", "--config"], out var values)
        || values.GetValueOrDefault("--audience") is not { } audience)
    {
        return Usage();
    }

    if (!TokenExchange.IsWellFormedAudience(audience))
    {
        Console.Error.WriteLine($"proof: --audience must be 1 to {TokenExchange.MaxAudienceLength} characters with no spaces.");
        return ExitCodes.Usage;
    }

    var wait = TimeSpan.Zero;
    if (values.GetValueOrDefault("--wait") is { } waitText)
    {
        if (!uint.TryParse(waitText, out var seconds))
        {
            return Usage();
        }

        wait = TimeSpan.FromSeconds(seconds);
    }

    var options = ClientOptions.Load(values.GetValueOrDefault("--config") ?? ClientOptions.DefaultPath);
    using var http = TokenExchangeClient.CreateHttpClient(options.LoadCaBundle());
    var commands = new ClientCommands(KvpReaders.ForThisMachine(), TimeProvider.System, Console.Out, Console.Error);
    return await commands.TokenAsync(options, http, audience, values.GetValueOrDefault("--out"), wait, cancel.Token);
}

int Status(string[] rest)
{
    if (!TryParse(rest, ["--config"], out var values))
    {
        return Usage();
    }

    // Status is for troubleshooting, so it reports a configuration problem instead of stopping at it.
    ClientOptions? options = null;
    string? configProblem = null;
    try
    {
        options = ClientOptions.Load(values.GetValueOrDefault("--config") ?? ClientOptions.DefaultPath);
        options.LoadCaBundle();
    }
    catch (ClientConfigException ex)
    {
        configProblem = ex.Message;
    }

    return new ClientCommands(KvpReaders.ForThisMachine(), TimeProvider.System, Console.Out, Console.Error).Status(options, configProblem);
}

/// <summary>Options as <c>--name value</c> pairs, each at most once.</summary>
static bool TryParse(string[] args, string[] allowed, out Dictionary<string, string> values)
{
    values = new(StringComparer.Ordinal);
    for (var i = 0; i < args.Length; i += 2)
    {
        if (!allowed.Contains(args[i]) || i + 1 >= args.Length || !values.TryAdd(args[i], args[i + 1]))
        {
            return false;
        }
    }

    return true;
}

static int Usage()
{
    Console.Error.WriteLine(Help);
    return ExitCodes.Usage;
}

static int PrintVersion()
{
    Console.WriteLine(typeof(ExitCodes).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion);
    return ExitCodes.Ok;
}
