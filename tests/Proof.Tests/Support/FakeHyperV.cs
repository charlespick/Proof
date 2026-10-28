using Proof.Refresher;
using Proof.Shared;

namespace Proof.Tests.Support;

/// <summary>An in-memory Hyper-V host: a set of running VMs and the KVP items written to each.</summary>
public sealed class FakeHyperV : IHyperVHost
{
    public List<VirtualMachine> Running { get; } = [];

    /// <summary>KVP items by VM ID, then key.</summary>
    public Dictionary<string, Dictionary<string, string>> Kvp { get; } = [];

    /// <summary>VM IDs whose writes fail.</summary>
    public HashSet<string> Failing { get; } = [];

    public int Writes { get; private set; }

    public Task<IReadOnlyList<VirtualMachine>> GetRunningVirtualMachinesAsync(CancellationToken cancellationToken)
    {
        lock (Running)
        {
            return Task.FromResult<IReadOnlyList<VirtualMachine>>(Running.ToList());
        }
    }

    public Task WriteKvpItemAsync(VirtualMachine vm, string name, string value, CancellationToken cancellationToken)
    {
        lock (Kvp)
        {
            Writes++;
            if (Failing.Contains(vm.Id))
            {
                throw new KvpWriteException("ModifyKvpItems failed with error 32768: test failure", 32768);
            }

            if (!Kvp.TryGetValue(vm.Id, out var items))
            {
                Kvp[vm.Id] = items = [];
            }

            items[name] = value;
            return Task.CompletedTask;
        }
    }

    public bool HasToken(VirtualMachine vm)
    {
        lock (Kvp)
        {
            return Kvp.TryGetValue(vm.Id, out var items) && items.ContainsKey(KvpKeys.Token);
        }
    }

    /// <summary>The live subscription, if any. Tests start VMs through it.</summary>
    public FakeSubscription? Subscription { get; private set; }

    public int Subscriptions { get; private set; }

    /// <summary>If set, subscribing throws this.</summary>
    public Exception? SubscribeFailure { get; set; }

    public IVmStartSubscription WatchVmStarts(Action<VirtualMachine> onStarted, Action onStopped)
    {
        if (SubscribeFailure is not null)
        {
            throw SubscribeFailure;
        }

        Subscriptions++;
        return Subscription = new FakeSubscription(onStarted, onStopped);
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
            s.Raise(vm);
        }
    }

    public sealed class FakeSubscription(Action<VirtualMachine> onStarted, Action onStopped) : IVmStartSubscription
    {
        public bool IsActive { get; private set; } = true;

        public void Raise(VirtualMachine vm) => onStarted(vm);

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
