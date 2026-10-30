using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Proof.Shared;

namespace Proof.Tests;

/// <summary>
/// The check on machine settings files, against real access lists. Making Administrators the owner needs an elevated
/// Windows session, so these skip elsewhere. Each test builds its own folder: locked down as an administrator would
/// make it, then loosened one way.
/// </summary>
public sealed class SettingsFileSecurityTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "proof-settings-tests-" + Guid.NewGuid().ToString("N"));

    public SettingsFileSecurityTests()
    {
        Assert.SkipUnless(
            OperatingSystem.IsWindows() && new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator),
            "Needs an elevated Windows session to give files to Administrators.");
    }

    private string SettingsPath => Path.Combine(directory, "settings.json");

    public void Dispose()
    {
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [SupportedOSPlatform("windows")]
    private static SecurityIdentifier Sid(WellKnownSidType type) => new(type, null);

    /// <summary>Owned by Administrators; SYSTEM and Administrators full control; Users read, inherited by the file.</summary>
    [SupportedOSPlatform("windows")]
    private void CreateLockedDown()
    {
        const InheritanceFlags both = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        var folder = new DirectorySecurity();
        folder.SetOwner(Sid(WellKnownSidType.BuiltinAdministratorsSid));
        folder.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        folder.AddAccessRule(new(Sid(WellKnownSidType.LocalSystemSid), FileSystemRights.FullControl, both, PropagationFlags.None, AccessControlType.Allow));
        folder.AddAccessRule(new(Sid(WellKnownSidType.BuiltinAdministratorsSid), FileSystemRights.FullControl, both, PropagationFlags.None, AccessControlType.Allow));
        folder.AddAccessRule(new(Sid(WellKnownSidType.BuiltinUsersSid), FileSystemRights.ReadAndExecute, both, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(directory).Create(folder);

        File.WriteAllText(SettingsPath, "{}");
        var file = new FileInfo(SettingsPath);
        var security = file.GetAccessControl();
        security.SetOwner(Sid(WellKnownSidType.BuiltinAdministratorsSid));
        file.SetAccessControl(security);
    }

    [SupportedOSPlatform("windows")]
    private void AllowUsers(
        FileSystemInfo target, FileSystemRights rights, InheritanceFlags inheritance = InheritanceFlags.None, PropagationFlags propagation = PropagationFlags.None)
    {
        var users = Sid(WellKnownSidType.BuiltinUsersSid);
        if (target is DirectoryInfo folder)
        {
            var security = folder.GetAccessControl();
            security.AddAccessRule(new(users, rights, inheritance, propagation, AccessControlType.Allow));
            folder.SetAccessControl(security);
        }
        else
        {
            var file = (FileInfo)target;
            var security = file.GetAccessControl();
            security.AddAccessRule(new(users, rights, AccessControlType.Allow));
            file.SetAccessControl(security);
        }
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void AcceptsSettingsOnlyAdministratorsCanChange()
    {
        CreateLockedDown();
        Assert.Null(SettingsFileSecurity.FindProblem(SettingsPath));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void AcceptsAMissingFile()
    {
        CreateLockedDown();
        Assert.Null(SettingsFileSecurity.FindProblem(Path.Combine(directory, "absent.json")));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void AcceptsAFolderUsersMayOnlyAddFilesTo()
    {
        // What %ProgramData% passes down to a folder an administrator creates in it: this folder and subfolders only.
        CreateLockedDown();
        AllowUsers(new DirectoryInfo(directory), FileSystemRights.CreateFiles | FileSystemRights.CreateDirectories, InheritanceFlags.ContainerInherit);
        Assert.Null(SettingsFileSecurity.FindProblem(SettingsPath));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void IgnoresRightsThatOnlyApplyToNewFiles()
    {
        // Applies to subfolders created later, not to the folder or its files.
        CreateLockedDown();
        AllowUsers(new DirectoryInfo(directory), FileSystemRights.Modify, InheritanceFlags.ContainerInherit, PropagationFlags.InheritOnly);
        Assert.Null(SettingsFileSecurity.FindProblem(SettingsPath));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void RefusesAFileUsersCanWrite()
    {
        CreateLockedDown();
        AllowUsers(new FileInfo(SettingsPath), FileSystemRights.Write);
        Assert.Contains("change it", SettingsFileSecurity.FindProblem(SettingsPath));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void RefusesAFolderUsersCanDeleteFilesFrom()
    {
        CreateLockedDown();
        AllowUsers(new DirectoryInfo(directory), FileSystemRights.DeleteSubdirectoriesAndFiles);
        Assert.Contains("replace its files", SettingsFileSecurity.FindProblem(SettingsPath));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void RefusesAFileAnotherAccountOwns()
    {
        CreateLockedDown();
        var file = new FileInfo(SettingsPath);
        var security = file.GetAccessControl();
        // The elevated user's own account stands in for a user who created the file first.
        security.SetOwner(WindowsIdentity.GetCurrent().User!);
        file.SetAccessControl(security);
        Assert.Contains("is owned by", SettingsFileSecurity.FindProblem(SettingsPath));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void RefusesAFolderAnotherAccountOwns()
    {
        CreateLockedDown();
        var folder = new DirectoryInfo(directory);
        var security = folder.GetAccessControl();
        security.SetOwner(WindowsIdentity.GetCurrent().User!);
        folder.SetAccessControl(security);
        Assert.Contains("is owned by", SettingsFileSecurity.FindProblem(SettingsPath));
    }
}
