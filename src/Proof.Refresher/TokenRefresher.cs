using System.Diagnostics.Metrics;
using Proof.Refresher.Metadata;
using Proof.Shared;

namespace Proof.Refresher;

/// <summary>What one pass did, for logs and the <c>once</c> command.</summary>
/// <param name="Results">The VMs the pass acted on or newly reported. VMs with nothing due are left out.</param>
public sealed record RefreshPass(int Running, IReadOnlyList<VmTokenResult> Results)
{
    public int Written => Results.Count(r => r.Outcome == VmTokenOutcome.Written);

    public int Refused => Results.Count(r => r.Outcome == VmTokenOutcome.Refused);

    public int Failed => Results.Count(r => r.Outcome == VmTokenOutcome.Failed);
}

public enum VmTokenOutcome
{
    /// <summary>A new host token was written.</summary>
    Written,

    /// <summary>The VM's notes have no <c>identity:</c> block, so it gets no token, and any token it had was removed.</summary>
    NotEnrolled,

    /// <summary>
    /// The VM's <c>identity:</c> block, or the block in its notes, cannot be used, or the token would not fit in one KVP
    /// value. It gets no token, and any token it had was removed.
    /// </summary>
    Refused,

    /// <summary>Hyper-V refused to write or remove the token. Retried on the next pass.</summary>
    Failed,
}

/// <param name="Identity">The identity in the token written, for <see cref="VmTokenOutcome.Written"/>.</param>
/// <param name="Detail">Why, for <see cref="VmTokenOutcome.Refused"/> and <see cref="VmTokenOutcome.Failed"/>. Never contains a token or a value from the notes.</param>
public sealed record VmTokenResult(
    VirtualMachine Vm,
    VmTokenOutcome Outcome,
    VmIdentity? Identity = null,
    string? Jti = null,
    DateTimeOffset? Expires = null,
    bool VmNameOmitted = false,
    string? Detail = null);

/// <summary>
/// One refresh pass: find the running VMs and give each one the host token its notes call for. A VM with a usable
/// <c>identity:</c> block is written a new token when this process has not yet written to it (it just started or
/// migrated in), when its identity differs from the one in its last token, or when that token is about
/// <see cref="HostTokenPolicy.RefreshInterval"/> old. A VM without one has its token removed, once. A failed write or
/// removal is retried on the next pass.
/// </summary>
public sealed class TokenRefresher
{
    private readonly IHyperVHost hyperV;
    private readonly HostTokenSigner signer;
    private readonly TimeProvider time;
    private readonly ILogger<TokenRefresher> logger;
    private readonly Counter<long> writes;
    private readonly Counter<long> removals;
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
        removals = meter.CreateCounter<long>("proof.refresher.kvp_removals", description: "Host tokens removed from VMs that no longer have a usable identity, by outcome.");
        meter.CreateObservableGauge(
            "proof.refresher.oldest_token_age",
            () => OldestTokenAge()?.TotalSeconds ?? 0,
            unit: "s",
            description: "Age of the oldest successful write among running VMs with an identity. Alert if it nears the host token lifetime.");
        meter.CreateObservableGauge("proof.refresher.running_vms", () => Count(_ => true), description: "Running VMs seen in the last pass.");
        meter.CreateObservableGauge(
            "proof.refresher.enrolled_vms", () => Count(s => s.Kind == VmKind.Enrolled), description: "Running VMs with a usable identity block.");
        meter.CreateObservableGauge(
            "proof.refresher.identity_errors",
            () => Count(s => s.Kind == VmKind.Refused),
            description: "Running VMs that get no host token because their identity block cannot be used or does not fit. The log says why.");
    }

    public const string MeterName = "Proof.Refresher";

    /// <param name="force">Write or remove every running VM's token, due or not.</param>
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
        var results = new List<VmTokenResult>();
        foreach (var vm in running)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var vmState = previous.GetValueOrDefault(vm.Id) ?? new VmState();
            next[vm.Id] = vmState;

            var now = time.GetUtcNow();
            var (identity, problem) = Evaluate(vm);
            if (identity is not null)
            {
                if (force || !identity.Equals(vmState.Signed) || IsDue(vmState, now))
                {
                    results.Add(await WriteAsync(vm, identity, vmState, now, cancellationToken));
                }
            }
            else if (force || !vmState.Cleared || vmState.Problem != problem)
            {
                results.Add(await RemoveAsync(vm, problem, vmState, now, cancellationToken));
            }
        }

        lock (gate)
        {
            state = next;
        }

        return new RefreshPass(running.Count, results);
    }

    /// <summary>
    /// True if <paramref name="vm"/>'s notes call for a different token from the one this process last wrote or
    /// removed: its identity was added, changed, removed or broken. False for a VM no pass has seen yet; its start
    /// event or the next pass covers it. Cheap, so it can run on a WMI thread for every notes change.
    /// </summary>
    public bool IdentityChanged(VirtualMachine vm)
    {
        VmState? s;
        lock (gate)
        {
            s = state.GetValueOrDefault(vm.Id);
        }

        if (s is null)
        {
            return false;
        }

        var (identity, problem) = Evaluate(vm);
        return identity is not null ? !identity.Equals(s.Signed) : !s.Cleared || s.Problem != problem;
    }

    /// <summary>The oldest last-successful write among running VMs with an identity, counting a VM never written as old as this process's first try.</summary>
    public TimeSpan? OldestTokenAge()
    {
        Dictionary<string, VmState> snapshot;
        lock (gate)
        {
            snapshot = state;
        }

        var now = time.GetUtcNow();
        DateTimeOffset? oldest = null;
        foreach (var s in snapshot.Values.Where(s => s.Kind == VmKind.Enrolled))
        {
            var since = s.LastSuccess ?? s.FirstAttempt;
            if (since is { } t && (oldest is null || t < oldest))
            {
                oldest = t;
            }
        }

        return oldest is { } o ? now - o : null;
    }

    private int Count(Func<VmState, bool> predicate)
    {
        lock (gate)
        {
            return state.Values.Count(predicate);
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

    /// <summary>The VM's identity, or null with no problem if its notes have none, or null and why it cannot be used.</summary>
    private static (VmIdentity? Identity, string? Problem) Evaluate(VirtualMachine vm)
    {
        try
        {
            return (VmMetadataBlock.Find(vm.Notes)?.Identity, null);
        }
        catch (VmMetadataException ex)
        {
            return (null, $"The block in its notes cannot be used. {ex.Message}");
        }
    }

    private async Task<VmTokenResult> WriteAsync(VirtualMachine vm, VmIdentity identity, VmState s, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var signed = signer.Sign(vm, identity, now);
        if (!signed.Fits)
        {
            // Identity claims are never dropped or shortened to make a token fit.
            return await RemoveAsync(
                vm,
                $"Its host token would be {signed.Token.Length} characters even without vm_name, over the {KvpLimits.MaxValueLength}-character KVP limit. Shorten its tenant, assigned-id or security-tags.",
                s,
                now,
                cancellationToken);
        }

        var wasRefused = s.Kind == VmKind.Refused;
        s.Kind = VmKind.Enrolled;
        s.Problem = null;
        s.Cleared = false;
        s.FirstAttempt ??= now;
        try
        {
            await hyperV.WriteKvpItemAsync(vm, KvpKeys.Token, signed.Token, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            writes.Add(1, new KeyValuePair<string, object?>("outcome", "failure"));
            var error = Describe(ex);
            LogFailure(vm, s, now, error);
            return new VmTokenResult(vm, VmTokenOutcome.Failed, identity, signed.Jti, Detail: error);
        }

        writes.Add(1, new KeyValuePair<string, object?>("outcome", "success"));
        if (s.FailingSince is not null)
        {
            logger.LogInformation("Host token write to VM {VmId} ({VmName}) recovered.", vm.Id, vm.Name);
        }
        else if (wasRefused)
        {
            logger.LogInformation("VM {VmId} ({VmName}): its identity can be used now; wrote its host token.", vm.Id, vm.Name);
        }
        else if (s.Signed is not null && !identity.Equals(s.Signed))
        {
            logger.LogInformation("VM {VmId} ({VmName}): its identity changed; wrote a token with the new one.", vm.Id, vm.Name);
        }

        s.Signed = identity;
        s.LastSuccess = now;
        s.FailingSince = null;
        s.LastFailureLog = null;

        if (signed.VmNameOmitted)
        {
            logger.LogWarning("VM {VmId}: vm_name left out of the host token to fit the {Limit}-character KVP limit.", vm.Id, KvpLimits.MaxValueLength);
        }

        logger.LogDebug("Wrote host token {Jti} for VM {VmId} ({VmName}), expires {Expires:O}.", signed.Jti, vm.Id, vm.Name, signed.Expires);
        return new VmTokenResult(vm, VmTokenOutcome.Written, identity, signed.Jti, signed.Expires, signed.VmNameOmitted);
    }

    /// <summary>
    /// Takes the token away from a VM that has no usable identity, so the normal client path stops getting the old
    /// one at once. A token already copied out of the VM stays valid until it expires.
    /// </summary>
    /// <param name="problem">Why its identity cannot be used, or null if its notes have none.</param>
    private async Task<VmTokenResult> RemoveAsync(VirtualMachine vm, string? problem, VmState s, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var outcome = problem is null ? VmTokenOutcome.NotEnrolled : VmTokenOutcome.Refused;
        var hadToken = s.Signed is not null;
        var newProblem = problem != s.Problem || s.Kind == VmKind.Enrolled;
        s.Kind = problem is null ? VmKind.NotEnrolled : VmKind.Refused;
        s.Problem = problem;
        s.Signed = null;
        s.LastSuccess = null;
        s.FirstAttempt = null;

        if (problem is not null && newProblem)
        {
            logger.LogError("VM {VmId} ({VmName}) gets no host token. {Problem}", vm.Id, vm.Name, problem);
        }

        if (!s.Cleared)
        {
            try
            {
                await hyperV.RemoveKvpItemAsync(vm, KvpKeys.Token, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                removals.Add(1, new KeyValuePair<string, object?>("outcome", "failure"));
                var error = Describe(ex);
                s.FailingSince ??= now;
                if (ShouldLogFailure(s, now))
                {
                    logger.LogWarning("Could not remove the host token from VM {VmId} ({VmName}); retrying next pass. {Error}", vm.Id, vm.Name, error);
                }

                return new VmTokenResult(vm, VmTokenOutcome.Failed, Detail: error);
            }

            removals.Add(1, new KeyValuePair<string, object?>("outcome", "success"));
            s.Cleared = true;
            s.FailingSince = null;
            s.LastFailureLog = null;
            if (hadToken)
            {
                logger.LogInformation(
                    "VM {VmId} ({VmName}): {Reason}; removed its host token.",
                    vm.Id, vm.Name, problem is null ? "its notes no longer have an identity block" : "its identity can no longer be used");
            }
            else
            {
                logger.LogDebug("VM {VmId} ({VmName}) has no usable identity block, so it gets no host token.", vm.Id, vm.Name);
            }
        }

        return new VmTokenResult(vm, outcome, Detail: problem);
    }

    private static string Describe(Exception ex) => ex is KvpWriteException ? ex.Message : $"{ex.GetType().Name}: {ex.Message}";

    /// <summary>
    /// Logs a failure when it starts and then once per refresh interval, not on every pass. It becomes an error
    /// once the VM's token has expired or never existed for a whole token lifetime.
    /// </summary>
    private void LogFailure(VirtualMachine vm, VmState s, DateTimeOffset now, string error)
    {
        s.FailingSince ??= now;
        if (!ShouldLogFailure(s, now))
        {
            return;
        }

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

    /// <summary>True for the first failure in a run, then once per refresh interval.</summary>
    private static bool ShouldLogFailure(VmState s, DateTimeOffset now)
    {
        if (s.LastFailureLog is { } logged && now - logged < HostTokenPolicy.RefreshInterval && now >= logged)
        {
            return false;
        }

        s.LastFailureLog = now;
        return true;
    }

    private enum VmKind
    {
        Unknown,
        Enrolled,
        NotEnrolled,
        Refused,
    }

    private sealed class VmState
    {
        /// <summary>What the VM's notes said at the last pass.</summary>
        public VmKind Kind { get; set; }

        /// <summary>The identity in the token this process last wrote to the VM, or null if it has written none since the VM's last change.</summary>
        public VmIdentity? Signed { get; set; }

        /// <summary>Why the VM's identity could not be used at the last pass, or null.</summary>
        public string? Problem { get; set; }

        /// <summary>Its token was removed after it lost a usable identity, so there is nothing more to remove.</summary>
        public bool Cleared { get; set; }

        public DateTimeOffset? FirstAttempt { get; set; }
        public DateTimeOffset? LastSuccess { get; set; }
        public DateTimeOffset? FailingSince { get; set; }
        public DateTimeOffset? LastFailureLog { get; set; }
    }
}
