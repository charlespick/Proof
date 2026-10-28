using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Proof.Refresher;

/// <summary>
/// What the service's virtual account, <c>NT SERVICE\proof-refresher</c>, needs beyond an ordinary account
/// (Design.md 8): membership of Hyper-V Administrators for the WMI KVP methods and VM events, read on the host key,
/// and an event log source registered for it, since only an administrator can register one. The MSI switches the
/// service to the account and grants these after it installs the service, and revokes the group membership when it
/// removes it.
/// </summary>
[SupportedOSPlatform("windows")]
public static class ServiceAccess
{
    public const string ServiceName = "proof-refresher";

    public static readonly NTAccount Account = new($@"NT SERVICE\{ServiceName}");

    /// <summary>BUILTIN\Hyper-V Administrators, whose name is localized.</summary>
    private static readonly SecurityIdentifier HyperVAdministrators = new("S-1-5-32-578");

    private const int ErrorMemberNotInAlias = 1377;
    private const int ErrorMemberInAlias = 1378;
    private const int ErrorNoSuchAlias = 1376;
    private const int NerrGroupNotFound = 2220;

    /// <summary>The virtual account's SID. It resolves only while the service is installed.</summary>
    public static SecurityIdentifier AccountSid()
    {
        try
        {
            return (SecurityIdentifier)Account.Translate(typeof(SecurityIdentifier));
        }
        catch (IdentityNotMappedException)
        {
            throw new InvalidOperationException($"{Account.Value} was not found. It exists once the {ServiceName} service is installed.");
        }
    }

    /// <summary>
    /// Sets the installed service to log on as its virtual account. Windows Installer cannot install a service under
    /// a virtual account (the account cannot be looked up before the service exists), so the MSI installs it as
    /// Local System and this switches it before it first starts. A virtual account has no password, and the password
    /// must be null: an empty string fails with error 1057.
    /// </summary>
    public static void RunAsVirtualAccount()
    {
        using var manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager.IsInvalid)
        {
            throw new InvalidOperationException($"Cannot open the service control manager: error {Marshal.GetLastPInvokeError()}.");
        }

        using var service = OpenService(manager, ServiceName, ServiceChangeConfig);
        if (service.IsInvalid)
        {
            throw new InvalidOperationException($"Cannot open the {ServiceName} service: error {Marshal.GetLastPInvokeError()}.");
        }

        if (!ChangeServiceConfig(service, ServiceNoChange, ServiceNoChange, ServiceNoChange, null, null, IntPtr.Zero, null, Account.Value, null, null))
        {
            throw new InvalidOperationException($"Cannot set the {ServiceName} service to run as {Account.Value}: error {Marshal.GetLastPInvokeError()}.");
        }
    }

    /// <summary>Adds the account to Hyper-V Administrators. Returns false if it was already a member.</summary>
    public static bool AddToHyperVAdministrators(SecurityIdentifier account) =>
        ChangeMembership(account, add: true);

    /// <summary>Removes the account from Hyper-V Administrators. Returns false if it was not a member.</summary>
    public static bool RemoveFromHyperVAdministrators(SecurityIdentifier account) =>
        ChangeMembership(account, add: false);

    /// <summary>Registers the service's event log source in the Application log. Returns false if it exists.</summary>
    public static bool EnsureEventSource()
    {
        // The same call the event log logger makes when it may, so the source looks as if the service had made it.
        if (EventLog.SourceExists(ServiceName))
        {
            return false;
        }

        EventLog.CreateEventSource(new EventSourceCreationData(ServiceName, "Application"));
        return true;
    }

    private static bool ChangeMembership(SecurityIdentifier account, bool add)
    {
        string group;
        try
        {
            group = HyperVAdministrators.Translate(typeof(NTAccount)).Value.Split('\\')[^1];
        }
        catch (IdentityNotMappedException)
        {
            throw new InvalidOperationException("This machine has no Hyper-V Administrators group. Install the Hyper-V role first.");
        }

        var sid = new byte[account.BinaryLength];
        account.GetBinaryForm(sid, 0);
        var pinned = GCHandle.Alloc(sid, GCHandleType.Pinned);
        try
        {
            var member = new LocalGroupMembersInfo0 { Sid = pinned.AddrOfPinnedObject() };
            var result = add
                ? NetLocalGroupAddMembers(null, group, 0, ref member, 1)
                : NetLocalGroupDelMembers(null, group, 0, ref member, 1);
            return result switch
            {
                0 => true,
                ErrorMemberInAlias when add => false,
                ErrorMemberNotInAlias when !add => false,
                ErrorNoSuchAlias or NerrGroupNotFound => throw new InvalidOperationException($"The local group '{group}' was not found."),
                _ => throw new InvalidOperationException($"Could not {(add ? "add" : "remove")} {account.Translate(typeof(NTAccount)).Value} {(add ? "to" : "from")} '{group}': error {result}."),
            };
        }
        finally
        {
            pinned.Free();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LocalGroupMembersInfo0
    {
        public IntPtr Sid;
    }

    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceChangeConfig = 0x0002;
    private const uint ServiceNoChange = 0xFFFFFFFF;

    private sealed class ServiceHandle() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
    {
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenService(ServiceHandle manager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig(
        ServiceHandle service, uint serviceType, uint startType, uint errorControl, string? binaryPathName,
        string? loadOrderGroup, IntPtr tagId, string? dependencies, string? serviceStartName, string? password,
        string? displayName);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupAddMembers(string? serverName, string groupName, int level, ref LocalGroupMembersInfo0 buffer, int totalEntries);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupDelMembers(string? serverName, string groupName, int level, ref LocalGroupMembersInfo0 buffer, int totalEntries);
}
