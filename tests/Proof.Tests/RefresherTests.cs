using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Proof.Issuer;
using Proof.Refresher;
using Proof.Shared;
using Proof.Tests.Support;
using System.Diagnostics.Metrics;

namespace Proof.Tests;

/// <summary>The refresher's signer and refresh loop, checked against the issuer's own validator.</summary>
public sealed class RefresherTests : IDisposable
{
    private static readonly VirtualMachine Web01 = new(TestHost.VmId, "web01");
    private static readonly VirtualMachine Db01 = new("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "db01");

    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ServiceProvider services = new ServiceCollection().AddMetrics().BuildServiceProvider();
    private readonly FakeHyperV hyperV = new();
    private readonly ManualTime time = new(DateTimeOffset.UtcNow);
    private readonly HostTokenSigner signer;
    private readonly TokenRefresher refresher;
    private readonly ValidatorHarness issuer;

    public RefresherTests()
    {
        signer = CreateSigner(new RefresherOptions { IssuerUrl = TestHost.IssuerUrl, HostId = "hv-host-01", Cluster = "prod" });
        refresher = new TokenRefresher(hyperV, signer, time, services.GetRequiredService<IMeterFactory>(), NullLogger<TokenRefresher>.Instance);
        issuer = new ValidatorHarness(AllowlistFor(signer, "hv-host-01", "prod"), enforceClusterScope: true);
    }

    public void Dispose()
    {
        issuer.Dispose();
        services.Dispose();
        key.Dispose();
    }

    private HostTokenSigner CreateSigner(RefresherOptions options) => new(key, Options.Create(options));

    private static string AllowlistFor(HostTokenSigner signer, string host, string? cluster) =>
        TestHost.Allowlist(
            $"  - host: {host}\n"
            + (cluster is null ? "" : $"    cluster: {cluster}\n")
            + "    keys:\n"
            + $"      - kid: {signer.Kid}\n"
            + "        status: active\n"
            + $"        jwk: {{ kty: EC, crv: P-256, x: {signer.Jwk.X}, y: {signer.Jwk.Y} }}\n");

    // Signing.

    [Fact]
    public async Task SignedTokenPassesIssuerValidation()
    {
        var signed = signer.Sign(Web01, DateTimeOffset.UtcNow);

        var result = await issuer.ValidateAsync(signed.Token);

        Assert.True(result.IsValid, result.Failure.ToString());
        Assert.Equal(TestHost.VmId, result.Identity!.VmId);
        Assert.Equal("hv-host-01", result.Identity.Host);
        Assert.Equal("web01", result.Identity.VmName);
        Assert.Equal("prod", result.Identity.Cluster);
        Assert.Equal(signed.Jti, result.Identity.Jti);
        Assert.False(signed.VmNameOmitted);
    }

    [Fact]
    public void TokenHasDesignHeaderAndClaims()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var jwt = new JsonWebToken(signer.Sign(Web01, now).Token);

        Assert.Equal(ProofAlgorithms.Signing, jwt.Alg);
        Assert.Equal(ProofTokenTypes.HostToken, jwt.Typ);
        Assert.Equal(signer.Kid, jwt.Kid);
        Assert.Equal(ProofKeys.ComputeKid(signer.Jwk), jwt.Kid);
        Assert.Equal("hv-host-01", jwt.Issuer);
        Assert.Equal([TestHost.IssuerUrl], jwt.Audiences);
        Assert.Equal(now, new DateTimeOffset(jwt.IssuedAt));
        Assert.Equal(now, new DateTimeOffset(jwt.ValidFrom));
        Assert.Equal(now + HostTokenPolicy.Lifetime, new DateTimeOffset(jwt.ValidTo));
        Assert.Matches("^[0-9a-f]{32}$", jwt.Id);
    }

    [Fact]
    public void JtiIsFreshEachTime()
    {
        var now = DateTimeOffset.UtcNow;
        Assert.NotEqual(signer.Sign(Web01, now).Jti, signer.Sign(Web01, now).Jti);
    }

    [Fact]
    public void TypicalTokenFitsWellInsideKvpLimit()
    {
        // Design.md 6.1 estimated 500 to 550 characters. Measured here with a realistic issuer URL and names.
        var s = CreateSigner(new RefresherOptions { IssuerUrl = "https://id.corp.example", HostId = "hv-host-01", Cluster = "prod" });
        var token = s.Sign(Web01, DateTimeOffset.UtcNow).Token;

        Assert.InRange(token.Length, 450, 600);
    }

    [Fact]
    public async Task LongVmNameIsLeftOutToFitOneKvpValue()
    {
        // 100 characters is the Hyper-V maximum; non-ASCII names grow when encoded.
        var vm = Web01 with { Name = new string('é', 100) + new string('漢', 100) };

        var signed = signer.Sign(vm, DateTimeOffset.UtcNow);

        Assert.True(signed.VmNameOmitted);
        Assert.InRange(signed.Token.Length, 1, KvpLimits.MaxValueLength);
        Assert.False(new JsonWebToken(signed.Token).TryGetClaim(ProofClaimNames.VmName, out _));
        Assert.True((await issuer.ValidateAsync(signed.Token)).IsValid);
    }

    [Fact]
    public void MaximumLengthAsciiVmNameStillFits()
    {
        var signed = signer.Sign(Web01 with { Name = new string('w', 100) }, DateTimeOffset.UtcNow);

        Assert.False(signed.VmNameOmitted);
        Assert.InRange(signed.Token.Length, 1, KvpLimits.MaxValueLength);
    }

    [Fact]
    public void RefusesSettingsThatCannotFitInKvp()
    {
        var options = new RefresherOptions { IssuerUrl = "https://" + new string('a', 600) + ".example", HostId = "hv-host-01" };

        var ex = Assert.Throws<InvalidOperationException>(() => CreateSigner(options));
        Assert.Contains("KVP limit", ex.Message);
    }

    [Fact]
    public async Task IssuerRefusesTokenWhenHostIdDoesNotMatchAllowlist()
    {
        var other = CreateSigner(new RefresherOptions { IssuerUrl = TestHost.IssuerUrl, HostId = "hv-host-02", Cluster = "prod" });

        var result = await issuer.ValidateAsync(other.Sign(Web01, DateTimeOffset.UtcNow).Token);

        Assert.Equal(HostTokenFailure.ValidationFailed, result.Failure);
    }

    [Fact]
    public async Task StandaloneHostOmitsCluster()
    {
        var standalone = CreateSigner(new RefresherOptions { IssuerUrl = TestHost.IssuerUrl, HostId = "hv-host-01" });
        using var harness = new ValidatorHarness(AllowlistFor(standalone, "hv-host-01", cluster: null));

        var token = standalone.Sign(Web01, DateTimeOffset.UtcNow).Token;

        Assert.False(new JsonWebToken(token).TryGetClaim(ProofClaimNames.Cluster, out _));
        Assert.True((await harness.ValidateAsync(token)).IsValid);
    }

    // Refresh loop.

    [Fact]
    public async Task FirstPassWritesEveryRunningVm()
    {
        hyperV.Running.AddRange([Web01, Db01]);

        var pass = await refresher.RefreshAsync(CancellationToken.None);

        Assert.Equal((2, 2, 0), (pass.Running, pass.Written, pass.Failed));
        foreach (var vm in new[] { Web01, Db01 })
        {
            var token = hyperV.Kvp[vm.Id][KvpKeys.Token];
            var result = await issuer.ValidateAsync(token);
            Assert.True(result.IsValid, result.Failure.ToString());
            Assert.Equal(vm.Id, result.Identity!.VmId);
            Assert.Equal(vm.Name, result.Identity.VmName);
        }
    }

    [Fact]
    public async Task RewritesOnlyNearRefreshInterval()
    {
        hyperV.Running.Add(Web01);
        await refresher.RefreshAsync(CancellationToken.None);
        var first = hyperV.Kvp[Web01.Id][KvpKeys.Token];

        time.Advance(HostTokenPolicy.RefreshInterval - TokenRefresher.RenewalSlack - TimeSpan.FromSeconds(1));
        Assert.Equal(0, (await refresher.RefreshAsync(CancellationToken.None)).Written);
        Assert.Equal(first, hyperV.Kvp[Web01.Id][KvpKeys.Token]);

        time.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(1, (await refresher.RefreshAsync(CancellationToken.None)).Written);
        Assert.NotEqual(first, hyperV.Kvp[Web01.Id][KvpKeys.Token]);
    }

    [Fact]
    public async Task ScheduledPassSlightlyEarlierThanLastWriteStillRenews()
    {
        // Passes are one refresh interval apart; a write late in one pass must not wait for the pass after next.
        hyperV.Running.Add(Web01);
        await refresher.RefreshAsync(CancellationToken.None);

        time.Advance(HostTokenPolicy.RefreshInterval - TimeSpan.FromSeconds(2));

        Assert.Equal(1, (await refresher.RefreshAsync(CancellationToken.None)).Written);
    }

    [Fact]
    public async Task NewlyStartedVmIsWrittenOnNextPass()
    {
        hyperV.Running.Add(Web01);
        await refresher.RefreshAsync(CancellationToken.None);

        hyperV.Running.Add(Db01);
        time.Advance(TimeSpan.FromSeconds(30));
        var pass = await refresher.RefreshAsync(CancellationToken.None);

        Assert.Equal([Db01], pass.Results.Select(r => r.Vm));
    }

    [Fact]
    public async Task FailedWriteIsRetriedNextPassAndOthersStillWritten()
    {
        hyperV.Running.AddRange([Web01, Db01]);
        hyperV.Failing.Add(Web01.Id);

        var pass = await refresher.RefreshAsync(CancellationToken.None);
        Assert.Equal((1, 1), (pass.Written, pass.Failed));
        Assert.Contains("32768", pass.Results.Single(r => r.Vm == Web01).Error);
        Assert.True(hyperV.Kvp.ContainsKey(Db01.Id));

        hyperV.Failing.Clear();
        time.Advance(TimeSpan.FromSeconds(30));
        pass = await refresher.RefreshAsync(CancellationToken.None);
        Assert.Equal([Web01], pass.Results.Select(r => r.Vm));
        Assert.Equal(0, pass.Failed);
    }

    [Fact]
    public async Task VmThatLeavesAndReturnsIsWrittenAtOnce()
    {
        // A VM migrated away and back carries the other host's token; this host must write its own promptly.
        hyperV.Running.Add(Web01);
        await refresher.RefreshAsync(CancellationToken.None);

        hyperV.Running.Clear();
        time.Advance(TimeSpan.FromSeconds(30));
        await refresher.RefreshAsync(CancellationToken.None);

        hyperV.Running.Add(Web01);
        time.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal(1, (await refresher.RefreshAsync(CancellationToken.None)).Written);
    }

    [Fact]
    public async Task ClockGoingBackMakesVmDue()
    {
        hyperV.Running.Add(Web01);
        await refresher.RefreshAsync(CancellationToken.None);

        time.Advance(TimeSpan.FromMinutes(-10));

        Assert.Equal(1, (await refresher.RefreshAsync(CancellationToken.None)).Written);
    }

    [Fact]
    public async Task ForceWritesVmsThatAreNotDue()
    {
        hyperV.Running.Add(Web01);
        await refresher.RefreshAsync(CancellationToken.None);

        Assert.Equal(1, (await refresher.RefreshAsync(CancellationToken.None, force: true)).Written);
    }

    [Fact]
    public async Task OldestTokenAgeTracksFailingVm()
    {
        hyperV.Running.AddRange([Web01, Db01]);
        await refresher.RefreshAsync(CancellationToken.None);

        hyperV.Failing.Add(Web01.Id);
        time.Advance(HostTokenPolicy.RefreshInterval);
        await refresher.RefreshAsync(CancellationToken.None);
        time.Advance(TimeSpan.FromMinutes(1));

        Assert.Equal(HostTokenPolicy.RefreshInterval + TimeSpan.FromMinutes(1), refresher.OldestTokenAge());
    }

    // Options.

    [Theory]
    [InlineData("https://proof.test", "hv-host-01", null, true)]
    [InlineData("https://proof.test", "hv-host-01", "prod", true)]
    [InlineData("http://proof.test", "hv-host-01", null, false)]
    [InlineData("https://proof.test/", "hv-host-01", null, false)]
    [InlineData("https://proof.test", "", null, false)]
    [InlineData("https://proof.test", "hv host", null, false)]
    [InlineData("https://proof.test", "hv-host-01: x", null, false)]
    [InlineData("https://proof.test", "hv-host-01", "", false)]
    [InlineData("https://proof.test", "hv-host-01", "-prod", false)]
    public void ValidatesOptions(string issuerUrl, string hostId, string? cluster, bool valid)
    {
        var result = new RefresherOptionsValidator().Validate(null, new RefresherOptions { IssuerUrl = issuerUrl, HostId = hostId, Cluster = cluster });

        Assert.Equal(valid, result.Succeeded);
    }

    [Fact]
    public void ScanIntervalMustNotExceedRefreshInterval()
    {
        var options = new RefresherOptions { IssuerUrl = TestHost.IssuerUrl, ScanInterval = HostTokenPolicy.RefreshInterval + TimeSpan.FromSeconds(1) };

        Assert.False(new RefresherOptionsValidator().Validate(null, options).Succeeded);
    }
}
