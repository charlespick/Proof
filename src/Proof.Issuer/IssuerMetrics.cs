using System.Diagnostics.Metrics;

namespace Proof.Issuer;

/// <summary>Counters for Design.md section 8 monitoring. Exported by whatever metrics pipeline the host wires up.</summary>
public sealed class IssuerMetrics
{
    public const string MeterName = "Proof.Issuer";

    private readonly Counter<long> exchanges;
    private readonly Counter<long> allowlistReloadFailures;

    public IssuerMetrics(IMeterFactory meterFactory)
    {
        var meter = meterFactory.Create(MeterName);
        exchanges = meter.CreateCounter<long>("proof.issuer.exchanges", description: "Token exchange requests, by outcome.");
        allowlistReloadFailures = meter.CreateCounter<long>("proof.issuer.allowlist.reload_failures", description: "Allowlist files refused.");
    }

    public void Exchange(string outcome) => exchanges.Add(1, new KeyValuePair<string, object?>("outcome", outcome));

    public void AllowlistReloadFailed() => allowlistReloadFailures.Add(1);
}
