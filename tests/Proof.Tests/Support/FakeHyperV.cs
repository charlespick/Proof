using Proof.Refresher;
using Proof.Shared;

namespace Proof.Tests.Support;

/// <summary>An in-memory Hyper-V host: a set of running VMs with their notes, and the KVP items written to each.</summary>
public sealed class FakeHyperV : IHyperVHost
{
    public List<VirtualMachine> Running { get; } = [];

    /// <summary>KVP items by VM ID, then key.</summary>
    public Dictionary<string, Dictionary<string, string>> Kvp { get; } = [];

    /// <summary>VM IDs whose writes and removals fail.</summary>
    public HashSet<string> Failing { get; } = [];

    public int Writes { get; private set; }

    public int Removals { get; private set; }

    /// <summary>How many times the VMs were listed: one per refresh pass.</summary>
    public int Listings { get; private set; }

    public Task<IReadOnlyList<VirtualMachine>> GetRunningVirtualMachinesAsync(CancellationToken cancellationToken)
    {
        lock (Running)
        {
            Listings++;
            return Task.FromResult<IReadOnlyList<VirtualMachine>>(Running.ToList());
        }
    }

    public Task WriteKvpItemAsync(VirtualMachine vm, string name, string value, CancellationToken cancellationToken)
    {
        lock (Kvp)
        {
            Writes++;
            ThrowIfFailing(vm);
            if (!Kvp.TryGetValue(vm.Id, out var items))
            {
                Kvp[vm.Id] = items = [];
            }

            items[name] = value;
            return Task.CompletedTask;
        }
    }

    public Task RemoveKvpItemAsync(VirtualMachine vm, string name, CancellationToken cancellationToken)
    {
        lock (Kvp)
        {
            Removals++;
            ThrowIfFailing(vm);
            if (Kvp.TryGetValue(vm.Id, out var items))
            {
                items.Remove(name);
            }

            return Task.CompletedTask;
        }
    }

    private void ThrowIfFailing(VirtualMachine vm)
    {
        if (Failing.Contains(vm.Id))
        {
            throw new KvpWriteException("ModifyKvpItems failed with error 32768: test failure", 32768);
        }
    }

    public bool HasToken(VirtualMachine vm) => Token(vm) is not null;

    public string? Token(VirtualMachine vm)
    {
        lock (Kvp)
        {
            return Kvp.TryGetValue(vm.Id, out var items) ? items.GetValueOrDefault(KvpKeys.Token) : null;
        }
    }

    /// <summary>The live subscription, if any. Tests start VMs and change notes through it.</summary>
    public FakeSubscription? Subscription { get; private set; }

    public int Subscriptions { get; private set; }

    /// <summary>If set, subscribing throws this.</summary>
    public Exception? SubscribeFailure { get; set; }

    public IVmSubscription WatchVms(Action<string, string> onStarted, Action<VirtualMachine> onNotesChanged, Action onStopped)
    {
        if (SubscribeFailure is not null)
        {
            throw SubscribeFailure;
        }

        Subscriptions++;
        return Subscription = new FakeSubscription(onStarted, onNotesChanged, onStopped);
    }

    /// <summary>Starts a VM: it is running from now on, and the subscription hears about it.</summary>
    public void Start(VirtualMachine vm)
    {
        lock (Running)
        {
            Running.Add(vm);
        }

        if (Subscription is { IsActive: true } s)
        {
            s.RaiseStarted(vm);
        }
    }

    /// <summary>Replaces a running VM's notes, and the subscription hears about it. Returns the VM as it is now.</summary>
    public VirtualMachine SetNotes(VirtualMachine vm, string? notes)
    {
        var changed = vm with { Notes = notes };
        lock (Running)
        {
            Running[Running.FindIndex(r => r.Id == vm.Id)] = changed;
        }

        if (Subscription is { IsActive: true } s)
        {
            s.RaiseNotesChanged(changed);
        }

        return changed;
    }

    public sealed class FakeSubscription(Action<string, string> onStarted, Action<VirtualMachine> onNotesChanged, Action onStopped) : IVmSubscription
    {
        public bool IsActive { get; private set; } = true;

        public void RaiseStarted(VirtualMachine vm) => onStarted(vm.Id, vm.Name);

        public void RaiseNotesChanged(VirtualMachine vm) => onNotesChanged(vm);

        /// <summary>Ends the subscription the way a WMI restart would.</summary>
        public void Drop()
        {
            IsActive = false;
            onStopped();
        }

        public void Dispose() => IsActive = false;
    }
}

/// <summary>A clock tests move by hand.</summary>
public sealed class ManualTime(DateTimeOffset start) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = start;

    public override DateTimeOffset GetUtcNow() => Now;

    public void Advance(TimeSpan by) => Now += by;
}

/// <summary>Notes with a block holding an identity, as an operator would write them.</summary>
public static class Notes
{
    public static string WithIdentity(string tenant = TestHost.Tenant, string assignedId = TestHost.AssignedId, string securityTags = "[puppet, ssh-ca]") =>
        "Owned by the web team.\r\n"
        + "#proof-metadata-begin\r\n"
        + "identity:\r\n"
        + $"  tenant: {tenant}\r\n"
        + $"  assigned-id: {assignedId}\r\n"
        + $"  security-tags: {securityTags}\r\n"
        + "meta-data:\r\n"
        + "  hostname: web01\r\n"
        + "#proof-metadata-end\r\n";

    public const string WithoutIdentity = "#proof-metadata-begin\r\nmeta-data:\r\n  hostname: web01\r\n#proof-metadata-end\r\n";
}
