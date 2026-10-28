using Microsoft.Extensions.Diagnostics.HealthChecks;
using Proof.Issuer.Allowlist;

namespace Proof.Issuer;

/// <summary>A pod is ready only once an allowlist has loaded (Design.md 8).</summary>
public sealed class AllowlistReadinessCheck(AllowlistMonitor monitor) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var list = monitor.Current;
        if (list is null)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("No host allowlist is loaded."));
        }

        // A refused newer file does not make the pod unready: it keeps serving the previous list, and the
        // failure is alerted on through logs and the reload-failure counter.
        return Task.FromResult(HealthCheckResult.Healthy($"Allowlist {list.Sha256} loaded."));
    }
}
