using System.Diagnostics.Metrics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Proof.Issuer;
using Proof.Issuer.Allowlist;

namespace Proof.Tests.Support;

/// <summary>A <see cref="HostTokenValidator"/> over an allowlist file, without the web host.</summary>
public sealed class ValidatorHarness : IDisposable
{
    private readonly string directory = Directory.CreateTempSubdirectory("proof-validator-tests-").FullName;
    private readonly ServiceProvider services = new ServiceCollection().AddMetrics().BuildServiceProvider();

    public ValidatorHarness(string allowlistYaml, bool enforceClusterScope = false)
    {
        Options = new IssuerOptions
        {
            IssuerUrl = TestHost.IssuerUrl,
            AllowlistPath = Path.Combine(directory, "allowlist.yaml"),
            SigningKeyPath = "unused",
            EnforceClusterScope = enforceClusterScope,
        };
        Monitor = new AllowlistMonitor(
            Microsoft.Extensions.Options.Options.Create(Options),
            TimeProvider.System,
            new IssuerMetrics(services.GetRequiredService<IMeterFactory>()),
            NullLogger<AllowlistMonitor>.Instance);
        WriteAllowlist(allowlistYaml);
        Validator = new HostTokenValidator(Monitor, Microsoft.Extensions.Options.Options.Create(Options));
    }

    public IssuerOptions Options { get; }
    public AllowlistMonitor Monitor { get; }
    public HostTokenValidator Validator { get; }

    /// <summary>Writes the file and reloads, as the poll loop would.</summary>
    public void WriteAllowlist(string yaml)
    {
        File.WriteAllText(Options.AllowlistPath, yaml);
        Monitor.Reload();
    }

    public Task<HostTokenResult> ValidateAsync(string token) => Validator.ValidateAsync(token);

    public void Dispose()
    {
        services.Dispose();
        Directory.Delete(directory, recursive: true);
    }
}
