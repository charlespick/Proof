using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Proof.Shared;

/// <summary>
/// Checks that a machine settings file under <c>%ProgramData%</c> can be changed only by administrators. Any user may
/// create folders and files under <c>%ProgramData%</c> and then owns them, so a user could create the settings folder
/// or file before an administrator does and change the settings later.
/// </summary>
/// <remarks>
/// Only checks, never repairs: rewriting access lists as an administrator in a folder another user may have prepared
/// would follow that user's links. The folder's default access, inherited from <c>%ProgramData%</c>, passes: users
/// may add files to it, which is harmless, but cannot change or remove the files an administrator wrote.
/// </remarks>
[SupportedOSPlatform("windows")]
public static class SettingsFileSecurity
{
    private const FileSystemRights GenericWrite = (FileSystemRights)0x40000000;
    private const FileSystemRights GenericAll = (FileSystemRights)0x10000000;

    /// <summary>Rights that let the holder change, replace or re-permission the settings file.</summary>
    private const FileSystemRights FileChangeRights =
        FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete
        | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | GenericWrite | GenericAll;

    /// <summary>Rights on the folder that let the holder remove or replace the files in it, or re-permission it.</summary>
    private const FileSystemRights FolderChangeRights =
        FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.Delete
        | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | GenericAll;

    private static readonly HashSet<SecurityIdentifier> Trusted =
    [
        new(WellKnownSidType.LocalSystemSid, null),
        new(WellKnownSidType.BuiltinAdministratorsSid, null),
        // TrustedInstaller, which owns much of Windows itself.
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"),
        // OWNER RIGHTS stands for the owner, which must already be one of the above.
        new("S-1-3-4"),
    ];

    /// <summary>
    /// Why <paramref name="path"/> or its folder could be changed by an account other than SYSTEM or an administrator,
    /// or null if it cannot. A missing file is not a problem here.
    /// </summary>
    public static string? FindProblem(string path)
    {
        var file = new FileInfo(path);
        if (!file.Exists)
        {
            return null;
        }

        return Check(file.Directory!, FolderChangeRights) ?? Check(file, FileChangeRights);
    }

    private static string? Check(FileSystemInfo target, FileSystemRights changeRights)
    {
        // Attributes describe a link itself, not what it points to.
        if (target.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            return $"{target.FullName} is a link. Replace it with a real {(target is DirectoryInfo ? "folder" : "file")} created by an administrator.";
        }

        FileSystemSecurity security;
        try
        {
            security = target is DirectoryInfo directory
                ? directory.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access)
                : ((FileInfo)target).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return $"Cannot read the permissions of {target.FullName}: {ex.Message}";
        }

        var fix = $"Check its contents, then run elevated: icacls \"{target.FullName}\" /setowner *S-1-5-32-544";
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !Trusted.Contains(owner))
        {
            return $"{target.FullName} is owned by {Describe(security.GetOwner(typeof(SecurityIdentifier)))}, not SYSTEM or Administrators, so that account could change it. {fix}";
        }

        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow
                && !rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly)
                && (rule.FileSystemRights & changeRights) != 0
                && !(rule.IdentityReference is SecurityIdentifier sid && Trusted.Contains(sid)))
            {
                return $"{target.FullName} lets {Describe(rule.IdentityReference)} change {(target is DirectoryInfo ? "or replace its files" : "it")}. "
                    + $"Remove that permission, for example: icacls \"{target.FullName}\" /remove:g *{rule.IdentityReference.Value}";
            }
        }

        return null;
    }

    private static string Describe(IdentityReference? identity)
    {
        if (identity is null)
        {
            return "no one";
        }

        try
        {
            return $"{identity.Translate(typeof(NTAccount)).Value} ({identity.Value})";
        }
        catch (IdentityNotMappedException)
        {
            return identity.Value;
        }
    }
}
