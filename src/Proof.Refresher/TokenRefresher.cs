using System.Diagnostics.Metrics;
using Proof.Shared;

namespace Proof.Refresher;

/// <summary>What one pass did, for logs and the <c>once</c> command.</summary>
public sealed record RefreshPass(int Running, int Written, int Failed, IReadOnlyList<VmWriteResult> Results);

/// <param name="Error">Why the write failed; null on success. Never contains a token.</param>
public sealed record VmWriteResult(VirtualMachine Vm, string? Jti, DateTimeOffset? Expires, bool VmNameOmitted, string? Error);

/// <summary>
/// One refresh pass: find the running VMs and write a new host token to each one that is due (Design.md 6.1, 6.2).
/// A VM is due when this process has not yet written to it (it just started or migrated in), or its last
/// successful write is about <see cref="HostTokenPolicy.RefreshInterval"/> old. A failed write is retried on the next pass.
/// </summary>
public sealed class TokenRefresher
{
    private readonly IHyperVHost hyperV;
    private readonly HostTokenSigner signer;
    private readonly TimeProvider time;
    private readonly ILogger<TokenRefresher> logger;
    private readonly Counter<long> writes;
    private readonly object gate = new();
    private Dictionary<string, VmState> state = [];

    public TokenRefresher(IHyperVHost hyperV, HostTokenSigner signer, TimeProvider time, IMeterFactory meterFactory, ILogger<TokenRefresher> logger)
    {
        this.hyperV = hyperV;
        this.signer = signer;
        this.time = time;
        this.logger = logger;

        var meter = meterFactory.Create(MeterName);
        writes = meter.CreateCounter<long>("proof.refresher.kvp_writes", description: "Host token writes to VM KVP pools, by outcome.");
        meter.CreateObservableGauge(
            "proof.refresher.oldest_token_age",
            () => OldestTokenAge()?.TotalSeconds ?? 0,
            unit: "s",
            description: "Age of the oldest successful write among running VMs. Alert if it nears the host token lifetime.");
        meter.CreateObservableGauge("proof.refresher.running_vms", () => Count(), description: "Running VMs seen in the last pass.");
    }

    public const string MeterName = "Proof.Refresher";

    /// <param name="force">Write to every running VM, due or not.</param>
    /// <param name="filter">Only consider VMs this returns true for.</param>
    public async Task<RefreshPass> RefreshAsync(CancellationToken cancellationToken, bool force = false, Func<VirtualMachine, bool>? filter = null)
    {
        var running = await hyperV.GetRunningVirtualMachinesAsync(cancellationToken);
        if (filter is not null)
        {
            running = running.Where(filter).ToList();
        }

        Dictionary<string, VmState> previous;
        lock (gate)
        {
            previous = state;
        }

        // VMs that stopped or moved away are forgotten, so they are written to at once if they come back.
        var next = new Dictionary<string, VmState>(StringComparer.Ordinal);
        var results = new List<VmWriteResult>();
        foreach (var vm in running)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var vmState = previous.GetValueOrDefault(vm.Id) ?? new VmState();
            next[vm.Id] = vmState;

            var now = time.GetUtcNow();
            if (!force && !IsDue(vmState, now))
            {
                continue;
            }

            results.Add(await WriteAsync(vm, vmState, now, cancellationToken));
        }

        lock (gate)
        {
            state = next;
        }

        var failed = results.Count(r => r.Error is not null);
        return new RefreshPass(running.Count, results.Count - failed, failed, results);
    }

    /// <summary>The oldest last-successful write among running VMs, counting a VM never written as old as this process's first try.</summary>
    public TimeSpan? OldestTokenAge()
    {
        Dictionary<string, VmState> snapshot;
        lock (gate)
        {
            snapshot = state;
        }

        var now = time.GetUtcNow();
        DateTimeOffset? oldest = null;
        foreach (var s in snapshot.Values)
        {
            var since = s.LastSuccess ?? s.FirstAttempt;
            if (since is { } t && (oldest is null || t < oldest))
            {
                oldest = t;
            }
        }

        return oldest is { } o ? now - o : null;
    }

    private int Count()
    {
        lock (gate)
        {
            return state.Count;
        }
    }

    /// <summary>
    /// A token is renewed once it is this close to <see cref="HostTokenPolicy.RefreshInterval"/> old. Scheduled
    /// passes are one refresh interval apart, and without slack a write that landed a moment later in the previous
    /// pass would wait a whole extra interval.
    /// </summary>
    public static readonly TimeSpan RenewalSlack = TimeSpan.FromSeconds(30);

    private static bool IsDue(VmState s, DateTimeOffset now) =>
        s.LastSuccess is not { } last
        || now - last >= HostTokenPolicy.RefreshInterval - RenewalSlack
        || now < last; // The clock went back; do not trust the old timestamp.

    private async Task<VmWriteResult> WriteAsync(VirtualMachine vm, VmState s, DateTimeOffset now, CancellationToken cancellationToken)
    {
        s.FirstAttempt ??= now;
        SignedHostToken? signed = null;
        try
        {
            signed = signer.Sign(vm, now);
            await hyperV.WriteKvpItemAsync(vm, KvpKeys.Token, signed.Token, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            writes.Add(1, new KeyValuePair<string, object?>("outcome", "failure"));
            var error = ex is KvpWriteException ? ex.Message : $"{ex.GetType().Name}: {ex.Message}";
            LogFailure(vm, s, now, error);
            return new VmWriteResult(vm, signed?.Jti, null, signed?.VmNameOmitted ?? false, error);
        }

        writes.Add(1, new KeyValuePair<string, object?>("outcome", "success"));
        if (s.FailingSince is not null)
        {
            logger.LogInformation("Host token write to VM {VmId} ({VmName}) recovered.", vm.Id, vm.Name);
        }

        s.LastSuccess = now;
        s.FailingSince = null;
        s.LastFailureLog = null;

        if (signed.VmNameOmitted)
        {
            logger.LogWarning("VM {VmId}: vm_name left out of the host token to fit the {Limit}-character KVP limit.", vm.Id, KvpLimits.MaxValueLength);
        }

        logger.LogDebug("Wrote host token {Jti} for VM {VmId} ({VmName}), expires {Expires:O}.", signed.Jti, vm.Id, vm.Name, signed.Expires);
        return new VmWriteResult(vm, signed.Jti, signed.Expires, signed.VmNameOmitted, null);
    }

    /// <summary>
    /// Logs a failure when it starts and then once per refresh interval, not on every pass. It becomes an error
    /// once the VM's token has expired or never existed for a whole token lifetime.
    /// </summary>
    private void LogFailure(VirtualMachine vm, VmState s, DateTimeOffset now, string error)
    {
        s.FailingSince ??= now;
        if (s.LastFailureLog is { } logged && now - logged < HostTokenPolicy.RefreshInterval && now >= logged)
        {
            return;
        }

        s.LastFailureLog = now;
        var since = s.LastSuccess ?? s.FirstAttempt ?? now;
        if (now - since >= HostTokenPolicy.Lifetime)
        {
            logger.LogError("VM {VmId} ({VmName}) has had no host token write since {Since:O}; its token has expired. Last error: {Error}", vm.Id, vm.Name, since, error);
        }
        else
        {
            logger.LogWarning("Host token write to VM {VmId} ({VmName}) failed; retrying next pass. {Error}", vm.Id, vm.Name, error);
        }
    }

    private sealed class VmState
    {
        public DateTimeOffset? FirstAttempt { get; set; }
        public DateTimeOffset? LastSuccess { get; set; }
        public DateTimeOffset? FailingSince { get; set; }
        public DateTimeOffset? LastFailureLog { get; set; }
    }
}
