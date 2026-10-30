using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Proof.Refresher;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("proof-refresher runs on Hyper-V hosts (Windows) only.");
    return 1;
}

try
{
    return args switch
    {
        [] or ["run", ..] => Commands.Run(args.Skip(1).ToArray()),
        ["key", "create", .. var rest] => Commands.KeyCreate(rest),
        ["key", "show"] => Commands.KeyShow(),
        ["once", .. var rest] => await Commands.OnceAsync(rest),
        ["service", "grant"] => Commands.ServiceGrant(),
        ["service", "revoke"] => Commands.ServiceRevoke(),
        ["--version"] => Commands.Version(),
        _ => Commands.Usage(),
    };
}
catch (Exception ex) when (ex is OptionsValidationException or InvalidOperationException or CryptographicException or IdentityNotMappedException or UnauthorizedAccessException)
{
    // Settings, key and account problems: say what is wrong without a stack trace.
    Console.Error.WriteLine($"proof-refresher: {ex.Message}");
    return 1;
}

[SupportedOSPlatform("windows")]
internal static class Commands
{
    private const string Help = """
        proof-refresher                      Run the refresher (as a Windows service or in the console).
        proof-refresher key create [--grant <account>]...
                                             Create the host key (non-exportable, CNG software provider) and print
                                             its allowlist entry. --grant lets a service account sign with it,
                                             for example --grant "NT SERVICE\proof-refresher".
        proof-refresher key show             Print the host key's allowlist entry and who may use it.
        proof-refresher once [--vm <name or id>]
                                             Write a token to every running VM (or one VM) now, and report.
        proof-refresher service grant        Run the installed service as its virtual account, NT SERVICE\proof-refresher,
                                             and give that account what it needs: Hyper-V Administrators, read on
                                             the host key, and its event log source. The MSI runs it; run it again
                                             after creating a new host key.
        proof-refresher service revoke       Take the account out of Hyper-V Administrators.
        proof-refresher --version            Print the version.

        Settings come from appsettings.json next to the executable, then %ProgramData%\Proof\refresher.json,
        then environment variables (Proof__IssuerUrl, Proof__HostId, Proof__Cluster, Proof__HostKeyName,
        Proof__ScanInterval).
        """;

    public static int Usage()
    {
        Console.Error.WriteLine(Help);
        return 2;
    }

    public static int Version()
    {
        Console.WriteLine(typeof(Commands).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion);
        return 0;
    }

    public static int Run(string[] args)
    {
        var builder = CreateBuilder(args);
        builder.Services.AddWindowsService(options => options.ServiceName = "proof-refresher");
        builder.Services.AddHostedService<Worker>();

        using var host = builder.Build();
        // Fail at startup, not on the first pass, if the settings or the host key are wrong. Log it too, because a
        // service has no console: under the service host the logger writes to the Application event log.
        try
        {
            VerifyMachineSettings();
            host.Services.GetRequiredService<HostTokenSigner>();
        }
        catch (Exception ex)
        {
            host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Proof.Refresher").LogCritical("Cannot start: {Error}", ex.Message);
            throw;
        }

        host.Run();
        return 0;
    }

    public static int KeyCreate(string[] args)
    {
        var grants = new List<NTAccount>();
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--grant" && i + 1 < args.Length)
            {
                grants.Add(new NTAccount(args[++i]));
            }
            else
            {
                return Usage();
            }
        }

        var options = LoadOptions();
        if (HostKeyStore.Exists(options.HostKeyName))
        {
            Console.Error.WriteLine($"Host key '{options.HostKeyName}' already exists. To rotate, set Proof:HostKeyName to a new name first.");
            return 1;
        }

        using var key = HostKeyStore.Create(options.HostKeyName, grants);
        Console.Error.WriteLine($"Created host key '{options.HostKeyName}' (machine key, {HostKeyStore.Provider.Provider}, not exportable).");
        PrintEntry(options, key);
        return 0;
    }

    public static int KeyShow()
    {
        var options = LoadOptions();
        if (!HostKeyStore.Exists(options.HostKeyName))
        {
            Console.Error.WriteLine($"Host key '{options.HostKeyName}' does not exist. Create it with: proof-refresher key create");
            return 1;
        }

        using var key = HostKeyStore.Open(options.HostKeyName);
        Console.Error.WriteLine($"Host key '{options.HostKeyName}' ({HostKeyStore.Provider.Provider}). Access:");
        foreach (var line in HostKeyStore.DescribeAccess(options.HostKeyName))
        {
            Console.Error.WriteLine($"  {line}");
        }

        PrintEntry(options, key);
        return 0;
    }

    public static int ServiceGrant()
    {
        var account = ServiceAccess.Account.Value;
        var sid = ServiceAccess.AccountSid();
        ServiceAccess.RunAsVirtualAccount();
        Console.Error.WriteLine($"The {ServiceAccess.ServiceName} service runs as {account}.");
        Console.Error.WriteLine(ServiceAccess.AddToHyperVAdministrators(sid)
            ? $"Added {account} to Hyper-V Administrators."
            : $"{account} is already in Hyper-V Administrators.");
        Console.Error.WriteLine(ServiceAccess.EnsureEventSource()
            ? $"Registered the event log source '{ServiceAccess.ServiceName}'."
            : $"The event log source '{ServiceAccess.ServiceName}' is already registered.");

        // The key last, and not an error when it cannot be granted: the service then refuses to start, and says why
        // in the event log, which the source registered above makes possible.
        RefresherOptions options;
        try
        {
            options = LoadOptions();
        }
        catch (Exception ex) when (ex is OptionsValidationException or InvalidDataException or FormatException or InvalidOperationException)
        {
            Console.Error.WriteLine($"Settings could not be read, so no host key was granted: {ex.Message}");
            return 0;
        }

        if (!HostKeyStore.Exists(options.HostKeyName))
        {
            Console.Error.WriteLine($"Host key '{options.HostKeyName}' does not exist, so it was not granted. Create it, then run: proof-refresher service grant");
            return 0;
        }

        Console.Error.WriteLine(HostKeyStore.GrantRead(options.HostKeyName, sid)
            ? $"Granted {account} read on host key '{options.HostKeyName}'."
            : $"{account} can already use host key '{options.HostKeyName}'.");
        return 0;
    }

    public static int ServiceRevoke()
    {
        var account = ServiceAccess.Account.Value;
        Console.Error.WriteLine(ServiceAccess.RemoveFromHyperVAdministrators(ServiceAccess.AccountSid())
            ? $"Removed {account} from Hyper-V Administrators."
            : $"{account} was not in Hyper-V Administrators.");
        return 0;
    }

    public static async Task<int> OnceAsync(string[] args)
    {
        string? only = null;
        if (args is ["--vm", var vm])
        {
            only = vm;
        }
        else if (args.Length != 0)
        {
            return Usage();
        }

        VerifyMachineSettings();
        using var host = CreateBuilder([]).Build();
        var refresher = host.Services.GetRequiredService<TokenRefresher>();
        var pass = await refresher.RefreshAsync(
            CancellationToken.None,
            force: true,
            filter: only is null ? null : v => string.Equals(v.Name, only, StringComparison.OrdinalIgnoreCase) || string.Equals(v.Id, only, StringComparison.OrdinalIgnoreCase));

        if (only is not null && pass.Running == 0)
        {
            Console.Error.WriteLine($"No running VM named '{only}' or with that ID.");
            return 1;
        }

        foreach (var r in pass.Results)
        {
            Console.WriteLine(r.Error is null
                ? $"ok      {r.Vm.Id}  {r.Vm.Name}  jti {r.Jti}, expires {r.Expires:O}{(r.VmNameOmitted ? " (vm_name omitted)" : "")}"
                : $"failed  {r.Vm.Id}  {r.Vm.Name}  {r.Error}");
        }

        Console.WriteLine($"{pass.Running} running, {pass.Written} written, {pass.Failed} failed.");
        return pass.Failed == 0 ? 0 : 1;
    }

    private static HostApplicationBuilder CreateBuilder(string[] args)
    {
        // As a service the working directory is System32, so settings are found next to the executable.
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = args,
            ContentRootPath = AppContext.BaseDirectory,
        });
        // Machine settings sit outside the install directory so upgrades keep them. Environment variables and
        // arguments are added again after them so they still win.
        builder.Configuration.AddJsonFile(MachineSettingsPath, optional: true, reloadOnChange: false);
        builder.Configuration.AddEnvironmentVariables();
        builder.Configuration.AddCommandLine(args);

        builder.Services.AddOptions<RefresherOptions>()
            .BindConfiguration(RefresherOptions.SectionName)
            .ValidateOnStart();
        builder.Services.AddSingleton<IValidateOptions<RefresherOptions>, RefresherOptionsValidator>();

        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.AddMetrics();
        builder.Services.AddSingleton<IHyperVHost, WmiHyperVHost>();
        builder.Services.AddSingleton(sp => HostKeyStore.Open(sp.GetRequiredService<IOptions<RefresherOptions>>().Value.HostKeyName));
        builder.Services.AddSingleton<HostTokenSigner>();
        builder.Services.AddSingleton<TokenRefresher>();
        return builder;
    }

    private static string MachineSettingsPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Proof", "refresher.json");

    /// <summary>
    /// Refuses machine settings that someone other than SYSTEM or an administrator could have changed: they name the
    /// host, its cluster and its key.
    /// </summary>
    private static void VerifyMachineSettings()
    {
        if (Proof.Shared.SettingsFileSecurity.FindProblem(MachineSettingsPath) is { } problem)
        {
            throw new InvalidOperationException($"Refusing the machine settings. {problem}");
        }
    }

    /// <summary>Options for the key commands. The issuer URL is not needed to manage the key.</summary>
    private static RefresherOptions LoadOptions()
    {
        VerifyMachineSettings();
        var configuration = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: true)
            .AddJsonFile(MachineSettingsPath, optional: true)
            .AddEnvironmentVariables()
            .Build();
        var options = new RefresherOptions();
        configuration.GetSection(RefresherOptions.SectionName).Bind(options);

        var errors = new RefresherOptionsValidator().Validate(null, options).Failures?
            .Where(f => !f.StartsWith("Proof:IssuerUrl", StringComparison.Ordinal))
            .ToList() ?? [];
        if (errors.Count > 0)
        {
            throw new OptionsValidationException(RefresherOptions.SectionName, typeof(RefresherOptions), errors);
        }

        return options;
    }

    /// <summary>The allowlist entry for this host (Design.md 7.2), on stdout so it can be piped into a pull request.</summary>
    private static void PrintEntry(RefresherOptions options, ECDsa key)
    {
        var jwk = Proof.Shared.ProofKeys.CreatePublicJwk(key);
        Console.Error.WriteLine("Add this entry under hosts: in the issuer allowlist (or add the key to this host's existing entry):");
        Console.WriteLine($"  - host: {options.HostId}");
        if (options.Cluster is not null)
        {
            Console.WriteLine($"    cluster: {options.Cluster}");
        }

        Console.WriteLine("    keys:");
        Console.WriteLine($"      - kid: {jwk.Kid}");
        Console.WriteLine("        status: active");
        Console.WriteLine($"        jwk: {{ kty: EC, crv: P-256, x: {jwk.X}, y: {jwk.Y} }}");
    }
}
