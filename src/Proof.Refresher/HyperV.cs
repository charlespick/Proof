using System.Management;
using System.Runtime.Versioning;

namespace Proof.Refresher;

/// <summary>The two things the refresher needs from Hyper-V. Faked in tests.</summary>
public interface IHyperVHost
{
    /// <summary>The VMs running on this host now.</summary>
    Task<IReadOnlyList<VirtualMachine>> GetRunningVirtualMachinesAsync(CancellationToken cancellationToken);

    /// <summary>Creates or replaces a key in the VM's KVP External pool.</summary>
    Task WriteKvpItemAsync(VirtualMachine vm, string name, string value, CancellationToken cancellationToken);

    /// <summary>
    /// Calls <paramref name="onStarted"/> when a VM starts running on this host, including one arriving by live
    /// migration, and <paramref name="onStopped"/> if the subscription ends on its own. Callbacks run on a WMI
    /// thread and must not block. Dispose the result to stop.
    /// </summary>
    IVmStartSubscription WatchVmStarts(Action<VirtualMachine> onStarted, Action onStopped);
}

/// <summary>A subscription that can end on its own, for example when the WMI service restarts.</summary>
public interface IVmStartSubscription : IDisposable
{
    bool IsActive { get; }
}

/// <summary>A KVP write that Hyper-V refused or that did not finish.</summary>
public sealed class KvpWriteException(string message, uint errorCode = 0) : Exception(message)
{
    public uint ErrorCode { get; } = errorCode;
}

/// <summary>
/// <see cref="IHyperVHost"/> over the Hyper-V WMI provider (<c>root\virtualization\v2</c>).
/// </summary>
/// <remarks>
/// Measured on Windows Server 2025 (Design.md 6.2): <c>ModifyKvpItems</c> fails with 32779 (not found) for a missing key, and
/// <c>AddKvpItems</c> fails with 32773 (invalid parameter) for an existing one, so an upsert is Modify, then Add
/// (Design.md 6.2). Both work whether or not the VM is running and whether or not its Data Exchange service is on;
/// the guest sees the item once both are.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WmiHyperVHost : IHyperVHost
{
    private const string Namespace = @"\\.\root\virtualization\v2";

    // Msvm_ComputerSystem.EnabledState and the method and job codes in the Hyper-V WMI documentation.
    private const ushort EnabledStateEnabled = 2;
    private const uint ReturnCompleted = 0;
    private const uint ReturnJobStarted = 4096;
    private const uint ErrorInvalidParameter = 32773;
    private const uint ErrorInvalidState = 32775;
    private const uint ErrorNotFound = 32779;
    private const ushort JobStateCompleted = 7;

    private static readonly TimeSpan JobTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan InvalidStateRetryLimit = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan InvalidStateRetryDelay = TimeSpan.FromMilliseconds(250);

    public Task<IReadOnlyList<VirtualMachine>> GetRunningVirtualMachinesAsync(CancellationToken cancellationToken)
    {
        var scope = Connect();
        var result = new List<VirtualMachine>();
        using var searcher = new ManagementObjectSearcher(
            scope, new ObjectQuery("SELECT Name, ElementName, EnabledState FROM Msvm_ComputerSystem"));
        using var systems = searcher.Get();
        foreach (var system in systems.Cast<ManagementObject>())
        {
            using (system)
            {
                // The host itself is also an Msvm_ComputerSystem; VMs are the ones named by a GUID. Caption would
                // tell them apart too, but it is localized.
                if (Guid.TryParse(system["Name"] as string, out var id)
                    && system["EnabledState"] is ushort state
                    && state == EnabledStateEnabled)
                {
                    result.Add(new VirtualMachine(id.ToString("D"), system["ElementName"] as string ?? ""));
                }
            }
        }

        return Task.FromResult<IReadOnlyList<VirtualMachine>>(result);
    }

    public async Task WriteKvpItemAsync(VirtualMachine vm, string name, string value, CancellationToken cancellationToken)
    {
        var scope = Connect();
        using var service = GetSingle(scope, "SELECT * FROM Msvm_VirtualSystemManagementService");
        // The ID came from Guid.ToString, so it is safe to put in the query.
        using var system = GetSingle(scope, $"SELECT * FROM Msvm_ComputerSystem WHERE Name = '{Guid.Parse(vm.Id):D}'");
        var item = CreateDataItem(scope, name, value);

        // A VM that has just migrated in reports Running a moment before it accepts KVP writes, and refuses them with
        // 32775 (invalid state) until then: about 200 ms on Windows Server 2025. Retry briefly rather than wait for
        // the next pass.
        var deadline = DateTime.UtcNow + InvalidStateRetryLimit;
        var result = await UpsertAsync(scope, service, system, item, cancellationToken);
        while (result.Code == ErrorInvalidState && DateTime.UtcNow < deadline)
        {
            await Task.Delay(InvalidStateRetryDelay, cancellationToken);
            result = await UpsertAsync(scope, service, system, item, cancellationToken);
        }

        if (result.Code != ReturnCompleted)
        {
            throw new KvpWriteException(result.Message ?? $"KVP write failed with error {result.Code}.", result.Code);
        }
    }

    private static async Task<(uint Code, string? Message)> UpsertAsync(
        ManagementScope scope, ManagementObject service, ManagementObject system, string item, CancellationToken cancellationToken)
    {
        var result = await InvokeAsync(scope, service, system, "ModifyKvpItems", item, cancellationToken);
        if (result.Code == ErrorNotFound)
        {
            result = await InvokeAsync(scope, service, system, "AddKvpItems", item, cancellationToken);
            if (result.Code == ErrorInvalidParameter)
            {
                // Someone added it between the two calls.
                result = await InvokeAsync(scope, service, system, "ModifyKvpItems", item, cancellationToken);
            }
        }

        return result;
    }

    /// <remarks>
    /// The Hyper-V provider raises intrinsic events itself, so no <c>WITHIN</c> polling clause is needed; measured on
    /// Windows Server 2025, events arrive within milliseconds of the state change. The provider also raises many
    /// modification events that change nothing, so the query keeps only running VMs and the handler drops
    /// modifications of a VM that was already running. A live migration arrives on the destination as a creation
    /// in state 10 (starting) followed by a change to 2 (running), and its KVP items come with it.
    /// </remarks>
    public IVmStartSubscription WatchVmStarts(Action<VirtualMachine> onStarted, Action onStopped)
    {
        var watcher = new ManagementEventWatcher(
            Connect(),
            new WqlEventQuery(
                "SELECT * FROM __InstanceOperationEvent WHERE TargetInstance ISA 'Msvm_ComputerSystem' "
                + $"AND TargetInstance.EnabledState = {EnabledStateEnabled}"));
        var subscription = new WmiSubscription(watcher);

        watcher.EventArrived += (_, e) =>
        {
            using var ev = e.NewEvent;
            if (ev.ClassPath.ClassName == "__InstanceDeletionEvent"
                || ev["TargetInstance"] is not ManagementBaseObject target
                || !Guid.TryParse(target["Name"] as string, out var id))
            {
                return;
            }

            if (ev.ClassPath.ClassName == "__InstanceModificationEvent"
                && ev["PreviousInstance"] is ManagementBaseObject previous
                && previous["EnabledState"] is ushort before
                && before == EnabledStateEnabled)
            {
                return;
            }

            onStarted(new VirtualMachine(id.ToString("D"), target["ElementName"] as string ?? ""));
        };
        watcher.Stopped += (_, _) =>
        {
            if (subscription.MarkStopped())
            {
                onStopped();
            }
        };
        watcher.Start();
        return subscription;
    }

    private sealed class WmiSubscription(ManagementEventWatcher watcher) : IVmStartSubscription
    {
        private volatile bool active = true;
        private volatile bool disposed;

        public bool IsActive => active;

        /// <summary>True if WMI ended the subscription, false if it was disposed.</summary>
        public bool MarkStopped()
        {
            active = false;
            return !disposed;
        }

        public void Dispose()
        {
            disposed = true;
            active = false;
            try
            {
                watcher.Stop();
            }
            catch (ManagementException)
            {
                // Already stopped by WMI.
            }

            watcher.Dispose();
        }
    }

    private static ManagementScope Connect()
    {
        var scope = new ManagementScope(Namespace);
        scope.Connect();
        return scope;
    }

    private static ManagementObject GetSingle(ManagementScope scope, string query)
    {
        using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(query));
        using var results = searcher.Get();
        var found = results.Cast<ManagementObject>().ToList();
        if (found.Count != 1)
        {
            foreach (var o in found)
            {
                o.Dispose();
            }

            throw new KvpWriteException($"Expected one result for {query}, found {found.Count}.");
        }

        return found[0];
    }

    /// <summary>An embedded Msvm_KvpExchangeDataItem in the DTD 2.0 text form the KVP methods take. Source 0 is the host.</summary>
    private static string CreateDataItem(ManagementScope scope, string name, string value)
    {
        using var itemClass = new ManagementClass(scope, new ManagementPath("Msvm_KvpExchangeDataItem"), null);
        using var item = itemClass.CreateInstance();
        item["Name"] = name;
        item["Data"] = value;
        item["Source"] = (ushort)0;
        return item.GetText(TextFormat.WmiDtd20);
    }

    /// <summary>Calls a KVP method and waits for its job. Returns 0 on success, or the Hyper-V error code and its description.</summary>
    private static async Task<(uint Code, string? Message)> InvokeAsync(
        ManagementScope scope, ManagementObject service, ManagementObject system, string method, string item, CancellationToken cancellationToken)
    {
        using var inParams = service.GetMethodParameters(method);
        inParams["TargetSystem"] = system.Path.Path;
        inParams["DataItems"] = new[] { item };
        using var outParams = service.InvokeMethod(method, inParams, null);
        var returnValue = (uint)outParams["ReturnValue"];
        if (returnValue != ReturnJobStarted)
        {
            return (returnValue, returnValue == ReturnCompleted ? null : $"{method} returned {returnValue}.");
        }

        using var job = new ManagementObject(scope, new ManagementPath((string)outParams["Job"]), null);
        var deadline = DateTime.UtcNow + JobTimeout;
        while (true)
        {
            job.Get();
            var state = (ushort)job["JobState"];
            if (state >= JobStateCompleted)
            {
                if (state == JobStateCompleted)
                {
                    return (ReturnCompleted, null);
                }

                // 32768 is the generic "failed" code, for a job that ended badly without one.
                uint code = job["ErrorCode"] is ushort c && c != 0 ? c : 32768u;
                return (code, $"{method} failed with error {code}: {job["ErrorDescription"]}");
            }

            if (DateTime.UtcNow > deadline)
            {
                throw new KvpWriteException($"{method} did not finish within {JobTimeout}.");
            }

            await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken);
        }
    }
}
