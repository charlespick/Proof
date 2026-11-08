using System.Management;
using System.Runtime.Versioning;

namespace Proof.Refresher;

/// <summary>A running VM on this host.</summary>
/// <param name="Id">The VM ID as a lowercase hyphenated GUID.</param>
/// <param name="Name">The VM name now. Mutable and informational.</param>
/// <param name="Notes">The VM's notes, where its <c>identity:</c> block is, or null if it has none.</param>
public sealed record VirtualMachine(string Id, string Name, string? Notes);

/// <summary>What the refresher needs from Hyper-V. Faked in tests.</summary>
public interface IHyperVHost
{
    /// <summary>The VMs running on this host now, with their notes.</summary>
    Task<IReadOnlyList<VirtualMachine>> GetRunningVirtualMachinesAsync(CancellationToken cancellationToken);

    /// <summary>Creates or replaces a key in the VM's KVP External pool.</summary>
    Task WriteKvpItemAsync(VirtualMachine vm, string name, string value, CancellationToken cancellationToken);

    /// <summary>Removes a key from the VM's KVP External pool. Removing a key that is not there succeeds.</summary>
    Task RemoveKvpItemAsync(VirtualMachine vm, string name, CancellationToken cancellationToken);

    /// <summary>
    /// Calls <paramref name="onStarted"/> with a VM's ID and name when it starts running on this host, including one
    /// arriving by live migration; <paramref name="onNotesChanged"/> when a VM's notes change, whether or not it is
    /// running; and <paramref name="onStopped"/> if the subscription ends on its own. Callbacks run on a WMI thread
    /// and must not block. Dispose the result to stop.
    /// </summary>
    IVmSubscription WatchVms(Action<string, string> onStarted, Action<VirtualMachine> onNotesChanged, Action onStopped);
}

/// <summary>A subscription that can end on its own, for example when the WMI service restarts.</summary>
public interface IVmSubscription : IDisposable
{
    bool IsActive { get; }
}

/// <summary>A KVP write that Hyper-V refused or that did not finish.</summary>
public sealed class KvpWriteException(string message, uint errorCode = 0) : Exception(message)
{
    public uint ErrorCode { get; } = errorCode;
}

/// <summary>A VM's settings that instance metadata reads.</summary>
/// <param name="BiosGuid">The SMBIOS UUID the guest sees. Instance IDs come from it.</param>
public sealed record VmSettings(Guid Id, string Name, Guid BiosGuid, string? Notes);

/// <summary>The VM settings instance metadata reads and writes, whether or not the VM is running. Faked in tests.</summary>
public interface IVmNotes
{
    /// <summary>The settings of a VM on this host, or null if it has none by that ID.</summary>
    Task<VmSettings?> GetVmAsync(Guid vmId, CancellationToken cancellationToken);

    /// <summary>Every VM on this host, running or not.</summary>
    Task<IReadOnlyList<VmSettings>> GetVmsAsync(CancellationToken cancellationToken);

    /// <summary>Replaces the VM's notes.</summary>
    Task WriteNotesAsync(Guid vmId, string notes, CancellationToken cancellationToken);

    /// <summary>Gives the VM a new BIOS GUID, and so a new instance ID. Hyper-V allows this only while the VM is off.</summary>
    Task WriteBiosGuidAsync(Guid vmId, Guid biosGuid, CancellationToken cancellationToken);
}

/// <summary>
/// <see cref="IHyperVHost"/> and <see cref="IVmNotes"/> over the Hyper-V WMI provider (<c>root\virtualization\v2</c>).
/// </summary>
/// <remarks>
/// Measured on Windows Server 2025: <c>ModifyKvpItems</c> fails with 32779 (not found) for a missing key, and
/// <c>AddKvpItems</c> fails with 32773 (invalid parameter) for an existing one, so an upsert is Modify, then Add.
/// <c>RemoveKvpItems</c> succeeds whether or not the key is there. All of them work whether or not the VM is running
/// and whether or not its Data Exchange service is on; the guest sees the change once both are.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WmiHyperVHost : IHyperVHost, IVmNotes
{
    private const string Namespace = @"\\.\root\virtualization\v2";

    // A VM's current settings, as opposed to those of its checkpoints.
    private const string RealizedSettings = "VirtualSystemType = 'Microsoft:Hyper-V:System:Realized'";

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
        var running = new List<(Guid Id, string Name)>();
        using (var searcher = new ManagementObjectSearcher(
            scope, new ObjectQuery("SELECT Name, ElementName, EnabledState FROM Msvm_ComputerSystem")))
        using (var systems = searcher.Get())
        {
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
                        running.Add((id, system["ElementName"] as string ?? ""));
                    }
                }
            }
        }

        // One query for every VM's notes rather than one per VM. A running VM always has settings; one missing here
        // was deleted between the two queries, and is left for the next pass.
        var notes = new Dictionary<Guid, string?>();
        using (var searcher = new ManagementObjectSearcher(
            scope, new ObjectQuery($"SELECT VirtualSystemIdentifier, Notes FROM Msvm_VirtualSystemSettingData WHERE {RealizedSettings}")))
        using (var settings = searcher.Get())
        {
            foreach (var s in settings.Cast<ManagementObject>())
            {
                using (s)
                {
                    if (Guid.TryParse(s["VirtualSystemIdentifier"] as string, out var id))
                    {
                        notes[id] = NotesOf(s);
                    }
                }
            }
        }

        return Task.FromResult<IReadOnlyList<VirtualMachine>>(running
            .Where(vm => notes.ContainsKey(vm.Id))
            .Select(vm => new VirtualMachine(vm.Id.ToString("D"), vm.Name, notes[vm.Id]))
            .ToList());
    }

    public Task WriteKvpItemAsync(VirtualMachine vm, string name, string value, CancellationToken cancellationToken) =>
        ChangeKvpAsync(vm, name, value, UpsertAsync, cancellationToken);

    public Task RemoveKvpItemAsync(VirtualMachine vm, string name, CancellationToken cancellationToken) =>
        ChangeKvpAsync(
            vm,
            name,
            "",
            (scope, service, system, item, ct) => InvokeAsync(scope, service, system, "RemoveKvpItems", item, ct),
            cancellationToken);

    private delegate Task<(uint Code, string? Message)> KvpChange(
        ManagementScope scope, ManagementObject service, ManagementObject system, string item, CancellationToken cancellationToken);

    private static async Task ChangeKvpAsync(VirtualMachine vm, string name, string value, KvpChange change, CancellationToken cancellationToken)
    {
        var scope = Connect();
        using var service = GetSingle(scope, "SELECT * FROM Msvm_VirtualSystemManagementService");
        // The ID came from Guid.ToString, so it is safe to put in the query.
        using var system = GetSingle(scope, $"SELECT * FROM Msvm_ComputerSystem WHERE Name = '{Guid.Parse(vm.Id):D}'");
        var item = CreateDataItem(scope, name, value);

        // A VM that has just migrated in reports Running a moment before it accepts KVP changes, and refuses them with
        // 32775 (invalid state) until then: about 200 ms on Windows Server 2025. Retry briefly rather than wait for
        // the next pass.
        var deadline = DateTime.UtcNow + InvalidStateRetryLimit;
        var result = await change(scope, service, system, item, cancellationToken);
        while (result.Code == ErrorInvalidState && DateTime.UtcNow < deadline)
        {
            await Task.Delay(InvalidStateRetryDelay, cancellationToken);
            result = await change(scope, service, system, item, cancellationToken);
        }

        if (result.Code != ReturnCompleted)
        {
            throw new KvpWriteException(result.Message ?? $"KVP change failed with error {result.Code}.", result.Code);
        }
    }

    public Task<VmSettings?> GetVmAsync(Guid vmId, CancellationToken cancellationToken)
    {
        var scope = Connect();
        // The ID is a Guid, so it is safe to put in the query.
        using var searcher = new ManagementObjectSearcher(
            scope, new ObjectQuery($"SELECT * FROM Msvm_VirtualSystemSettingData WHERE VirtualSystemIdentifier = '{vmId:D}' AND {RealizedSettings}"));
        using var results = searcher.Get();
        return Task.FromResult(results.Cast<ManagementObject>().Select(ReadSettings).OfType<VmSettings>().FirstOrDefault());
    }

    public Task<IReadOnlyList<VmSettings>> GetVmsAsync(CancellationToken cancellationToken)
    {
        var scope = Connect();
        using var searcher = new ManagementObjectSearcher(
            scope, new ObjectQuery($"SELECT * FROM Msvm_VirtualSystemSettingData WHERE {RealizedSettings}"));
        using var results = searcher.Get();
        return Task.FromResult<IReadOnlyList<VmSettings>>(results.Cast<ManagementObject>().Select(ReadSettings).OfType<VmSettings>().ToList());
    }

    public Task WriteNotesAsync(Guid vmId, string notes, CancellationToken cancellationToken) =>
        ModifySettingsAsync(vmId, s => s["Notes"] = new[] { notes }, cancellationToken);

    public Task WriteBiosGuidAsync(Guid vmId, Guid biosGuid, CancellationToken cancellationToken) =>
        ModifySettingsAsync(vmId, s => s["BIOSGUID"] = biosGuid.ToString("B").ToUpperInvariant(), cancellationToken);

    private static VmSettings? ReadSettings(ManagementObject settings)
    {
        using (settings)
        {
            return Guid.TryParse(settings["VirtualSystemIdentifier"] as string, out var id)
                && Guid.TryParse(settings["BIOSGUID"] as string, out var biosGuid)
                ? new VmSettings(id, settings["ElementName"] as string ?? "", biosGuid, NotesOf(settings))
                : null;
        }
    }

    /// <summary>An array, though Hyper-V's own tools write one element holding the whole text.</summary>
    private static string? NotesOf(ManagementBaseObject settings) =>
        settings["Notes"] is string[] notes ? string.Join("\r\n", notes) : null;

    /// <summary>
    /// The settings in the text form the method takes, with the notes as written. Left to itself GetText emits a bare
    /// CR, which the provider's XML parser drops, so a change to any setting would turn the CRLF of Hyper-V Manager's
    /// notes into LF, which its text box shows as one line. It also switches to CDATA when the text holds markup, so
    /// its output cannot be patched afterwards; instead a placeholder goes through it and the notes replace that.
    /// </summary>
    private static string SettingsText(ManagementObject settings)
    {
        if (settings["Notes"] is not string[] notes)
        {
            return settings.GetText(TextFormat.WmiDtd20);
        }

        var placeholder = Guid.NewGuid().ToString("N");
        settings["Notes"] = new[] { placeholder };
        return settings.GetText(TextFormat.WmiDtd20).Replace(placeholder, EscapeForWmiText(string.Join("\r\n", notes)));
    }

    /// <summary>A string as XML text that reads back exactly, line ends included.</summary>
    public static string EscapeForWmiText(string value) =>
        System.Security.SecurityElement.Escape(value).Replace("\r", "&#13;");

    private static async Task ModifySettingsAsync(Guid vmId, Action<ManagementObject> change, CancellationToken cancellationToken)
    {
        var scope = Connect();
        using var service = GetSingle(scope, "SELECT * FROM Msvm_VirtualSystemManagementService");
        using var settings = GetSingle(scope, $"SELECT * FROM Msvm_VirtualSystemSettingData WHERE VirtualSystemIdentifier = '{vmId:D}' AND {RealizedSettings}");
        change(settings);

        using var inParams = service.GetMethodParameters("ModifySystemSettings");
        inParams["SystemSettings"] = SettingsText(settings);
        using var outParams = service.InvokeMethod("ModifySystemSettings", inParams, null);
        var result = await FinishAsync(scope, "ModifySystemSettings", outParams, cancellationToken);
        if (result.Code != ReturnCompleted)
        {
            throw new KvpWriteException(result.Message ?? $"ModifySystemSettings failed with error {result.Code}.", result.Code);
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
    /// The Hyper-V provider raises intrinsic events itself, so no <c>WITHIN</c> polling clause is needed. Measured on
    /// Windows Server 2025:
    /// <list type="bullet">
    /// <item>VM state changes arrive within milliseconds. The provider also raises many modification events that change
    /// nothing, so the query keeps only running VMs and the handler drops modifications of a VM that was already
    /// running. A live migration arrives on the destination as a creation in state 10 (starting) followed by a change
    /// to 2 (running), and its KVP items come with it.</item>
    /// <item>A change to a VM's notes arrives about 100 ms after <c>Set-VM -Notes</c> returns, as a modification of its
    /// realized settings carrying the notes before and after. Changes to memory or processors, which are other
    /// classes, and starting the VM raise none; the handler still drops any whose notes are unchanged.</item>
    /// </list>
    /// </remarks>
    public IVmSubscription WatchVms(Action<string, string> onStarted, Action<VirtualMachine> onNotesChanged, Action onStopped)
    {
        var scope = Connect();
        var starts = new ManagementEventWatcher(
            scope,
            new WqlEventQuery(
                "SELECT * FROM __InstanceOperationEvent WHERE TargetInstance ISA 'Msvm_ComputerSystem' "
                + $"AND TargetInstance.EnabledState = {EnabledStateEnabled}"));
        var notes = new ManagementEventWatcher(
            scope,
            new WqlEventQuery(
                "SELECT * FROM __InstanceModificationEvent WHERE TargetInstance ISA 'Msvm_VirtualSystemSettingData' "
                + $"AND TargetInstance.{RealizedSettings}"));
        var subscription = new WmiSubscription([starts, notes], onStopped);

        starts.EventArrived += (_, e) =>
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

            onStarted(id.ToString("D"), target["ElementName"] as string ?? "");
        };
        notes.EventArrived += (_, e) =>
        {
            using var ev = e.NewEvent;
            if (ev["TargetInstance"] is not ManagementBaseObject target
                || !Guid.TryParse(target["VirtualSystemIdentifier"] as string, out var id))
            {
                return;
            }

            var now = NotesOf(target);
            if (ev["PreviousInstance"] is ManagementBaseObject previous && NotesOf(previous) == now)
            {
                return;
            }

            onNotesChanged(new VirtualMachine(id.ToString("D"), target["ElementName"] as string ?? "", now));
        };

        try
        {
            starts.Start();
            notes.Start();
        }
        catch
        {
            subscription.Dispose();
            throw;
        }

        return subscription;
    }

    /// <summary>Several watchers that live and die together: when WMI ends one, the owner renews them all.</summary>
    private sealed class WmiSubscription : IVmSubscription
    {
        private readonly ManagementEventWatcher[] watchers;
        private int stopped;
        private volatile bool disposed;

        public WmiSubscription(ManagementEventWatcher[] watchers, Action onStopped)
        {
            this.watchers = watchers;
            foreach (var watcher in watchers)
            {
                watcher.Stopped += (_, _) =>
                {
                    // Once, and not for a stop that Dispose caused.
                    if (Interlocked.Exchange(ref stopped, 1) == 0 && !disposed)
                    {
                        onStopped();
                    }
                };
            }
        }

        public bool IsActive => Volatile.Read(ref stopped) == 0 && !disposed;

        public void Dispose()
        {
            disposed = true;
            foreach (var watcher in watchers)
            {
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
        return await FinishAsync(scope, method, outParams, cancellationToken);
    }

    /// <summary>Waits for the job a method started, if it started one. Returns 0 on success, or the Hyper-V error code and its description.</summary>
    private static async Task<(uint Code, string? Message)> FinishAsync(
        ManagementScope scope, string method, ManagementBaseObject outParams, CancellationToken cancellationToken)
    {
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
