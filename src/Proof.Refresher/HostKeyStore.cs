using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Proof.Shared;

namespace Proof.Refresher;

/// <summary>
/// The host key: an ECDSA P-256 machine key in the CNG Microsoft Software Key Storage Provider, which every Windows
/// host has. It is created non-exportable, so the private key never leaves CNG; only the public key is read out.
/// </summary>
[SupportedOSPlatform("windows")]
public static class HostKeyStore
{
    public static readonly CngProvider Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;

    /// <summary>NCRYPT_SECURITY_DESCR_PROPERTY, set with DACL_SECURITY_INFORMATION.</summary>
    private const string SecurityDescriptorProperty = "Security Descr";
    private const CngPropertyOptions DaclSecurityInformation = (CngPropertyOptions)0x4;

    private const int GenericRead = unchecked((int)0x80000000);
    private const int GenericAll = 0x10000000;

    /// <summary>GENERIC_WRITE, DELETE, WRITE_DAC and WRITE_OWNER.</summary>
    private const int WriteOrDeleteRights = 0x40000000 | 0x00010000 | 0x00040000 | 0x00080000;

    public static bool Exists(string name) => CngKey.Exists(name, Provider, CngKeyOpenOptions.MachineKey);

    /// <summary>Opens the host key for signing. Throws if it does not exist or is not P-256.</summary>
    public static ECDsa Open(string name)
    {
        if (!Exists(name))
        {
            throw new InvalidOperationException($"Host key '{name}' does not exist. Create it with: proof-refresher key create");
        }

        using var key = CngKey.Open(name, Provider, CngKeyOpenOptions.MachineKey | CngKeyOpenOptions.Silent);
        var ecdsa = new ECDsaCng(key);
        if (!ProofKeys.IsP256(ecdsa))
        {
            ecdsa.Dispose();
            throw new InvalidOperationException($"Host key '{name}' is not ECDSA P-256.");
        }

        return ecdsa;
    }

    /// <summary>
    /// Creates a new non-exportable host key. Refuses to replace an existing key: a replaced key is a new
    /// allowlist entry (Design.md 7.3), so rotation uses a new name.
    /// </summary>
    /// <param name="grantRead">
    /// Accounts besides SYSTEM and Administrators that may sign with the key, such as the service's virtual
    /// account <c>NT SERVICE\proof-refresher</c>. Read access is what CNG requires to use a private key.
    /// </param>
    public static ECDsa Create(string name, IEnumerable<NTAccount> grantRead)
    {
        if (Exists(name))
        {
            throw new InvalidOperationException($"Host key '{name}' already exists. Use a new name to rotate.");
        }

        var parameters = new CngKeyCreationParameters
        {
            Provider = Provider,
            KeyCreationOptions = CngKeyCreationOptions.MachineKey,
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Signing,
        };
        parameters.Parameters.Add(new CngProperty(SecurityDescriptorProperty, BuildSecurityDescriptor(grantRead), DaclSecurityInformation));

        using var key = CngKey.Create(CngAlgorithm.ECDsaP256, name, parameters);
        return new ECDsaCng(key);
    }

    /// <summary>A protected DACL: full control for SYSTEM and Administrators, read for each granted account.</summary>
    private static byte[] BuildSecurityDescriptor(IEnumerable<NTAccount> grantRead)
    {
        var dacl = new DiscretionaryAcl(isContainer: false, isDS: false, capacity: 4);
        dacl.AddAccess(AccessControlType.Allow, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), GenericAll, InheritanceFlags.None, PropagationFlags.None);
        dacl.AddAccess(AccessControlType.Allow, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), GenericAll, InheritanceFlags.None, PropagationFlags.None);
        foreach (var account in grantRead)
        {
            SecurityIdentifier sid;
            try
            {
                sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
            }
            catch (IdentityNotMappedException)
            {
                throw new InvalidOperationException($"Account '{account.Value}' was not found. A service's virtual account exists once the service is installed.");
            }

            dacl.AddAccess(AccessControlType.Allow, sid, GenericRead, InheritanceFlags.None, PropagationFlags.None);
        }

        var descriptor = new CommonSecurityDescriptor(
            isContainer: false,
            isDS: false,
            ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected,
            owner: null,
            group: null,
            systemAcl: null,
            dacl);
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }

    /// <summary>The accounts allowed to use the key, for <c>key show</c>.</summary>
    public static IReadOnlyList<string> DescribeAccess(string name)
    {
        using var key = CngKey.Open(name, Provider, CngKeyOpenOptions.MachineKey | CngKeyOpenOptions.Silent);
        var bytes = key.GetProperty(SecurityDescriptorProperty, DaclSecurityInformation).GetValue() ?? [];
        var descriptor = new RawSecurityDescriptor(bytes, 0);
        var result = new List<string>();
        foreach (var ace in descriptor.DiscretionaryAcl ?? new RawAcl(GenericAcl.AclRevision, 0))
        {
            if (ace is CommonAce common)
            {
                string who;
                try
                {
                    who = common.SecurityIdentifier.Translate(typeof(NTAccount)).Value;
                }
                catch (IdentityNotMappedException)
                {
                    who = common.SecurityIdentifier.Value;
                }

                // CNG stores generic rights mapped to its own, so classify by bits: any write or delete right is
                // more than read.
                var rights = (common.AccessMask & (GenericAll | WriteOrDeleteRights)) != 0 ? "full control"
                    : (common.AccessMask & GenericRead) != 0 ? "read"
                    : $"0x{common.AccessMask:x8}";
                result.Add($"{common.AceQualifier} {who}: {rights}");
            }
        }

        return result;
    }
}
