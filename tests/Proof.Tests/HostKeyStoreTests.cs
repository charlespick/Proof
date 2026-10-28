using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Extensions.Options;
using Proof.Refresher;
using Proof.Shared;
using Proof.Tests.Support;

namespace Proof.Tests;

/// <summary>
/// The real CNG key store. Machine keys need an elevated Windows session, so these skip elsewhere.
/// Each test creates its own randomly named key and deletes it.
/// </summary>
public sealed class HostKeyStoreTests : IDisposable
{
    private readonly string name = "Proof Test Key " + Guid.NewGuid().ToString("N");

    public HostKeyStoreTests()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows() && IsElevated(), "Needs an elevated Windows session to create machine keys.");
    }

    public void Dispose()
    {
        if (OperatingSystem.IsWindows() && CngKey.Exists(name, HostKeyStore.Provider, CngKeyOpenOptions.MachineKey))
        {
            using var key = CngKey.Open(name, HostKeyStore.Provider, CngKeyOpenOptions.MachineKey);
            key.Delete();
        }
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void CreatedKeyIsNonExportableP256MachineKey()
    {
        using (HostKeyStore.Create(name, []))
        {
        }

        using var cng = CngKey.Open(name, HostKeyStore.Provider, CngKeyOpenOptions.MachineKey);
        Assert.True(cng.IsMachineKey);
        Assert.Equal(CngExportPolicies.None, cng.ExportPolicy);
        Assert.Equal(CngAlgorithm.ECDsaP256, cng.Algorithm);

        using var key = HostKeyStore.Open(name);
        Assert.True(ProofKeys.IsP256(key));
        Assert.ThrowsAny<CryptographicException>(() => key.ExportParameters(includePrivateParameters: true));
        Assert.ThrowsAny<CryptographicException>(() => key.ExportPkcs8PrivateKey());
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task OpenedKeySignsTokensTheIssuerAccepts()
    {
        string kid;
        using (var created = HostKeyStore.Create(name, []))
        {
            kid = ProofKeys.CreatePublicJwk(created).Kid;
        }

        using var key = HostKeyStore.Open(name);
        var signer = new HostTokenSigner(key, Options.Create(new RefresherOptions { IssuerUrl = TestHost.IssuerUrl, HostId = "hv-host-01" }));
        Assert.Equal(kid, signer.Kid);

        using var issuer = new ValidatorHarness(TestHost.Allowlist(
            "  - host: hv-host-01\n    keys:\n"
            + $"      - kid: {signer.Kid}\n        status: active\n"
            + $"        jwk: {{ kty: EC, crv: P-256, x: {signer.Jwk.X}, y: {signer.Jwk.Y} }}\n"));

        var result = await issuer.ValidateAsync(signer.Sign(new VirtualMachine(TestHost.VmId, "web01"), DateTimeOffset.UtcNow).Token);
        Assert.True(result.IsValid, result.Failure.ToString());
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void RefusesToReplaceExistingKey()
    {
        using (HostKeyStore.Create(name, []))
        {
        }

        Assert.Throws<InvalidOperationException>(() => HostKeyStore.Create(name, []));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void GrantAddsReadForAccount()
    {
        using (HostKeyStore.Create(name, [new NTAccount(@"NT AUTHORITY\NETWORK SERVICE")]))
        {
        }

        var access = HostKeyStore.DescribeAccess(name);
        Assert.Contains(access, a => a.Contains("NETWORK SERVICE", StringComparison.OrdinalIgnoreCase) && a.EndsWith("read", StringComparison.Ordinal));
        Assert.Contains(access, a => a.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(access, a => a.Contains("Administrators", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsElevated() =>
        OperatingSystem.IsWindows() && new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
}
