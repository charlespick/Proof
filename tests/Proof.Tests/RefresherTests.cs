using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Proof.Issuer;
using Proof.Refresher;
using Proof.Shared;
using Proof.Tests.Support;

namespace Proof.Tests;

/// <summary>The refresher's signer and refresh loop, checked against the issuer's own validator.</summary>
public sealed class RefresherTests : IDisposable
{
    private static readonly VirtualMachine Web01 = new(TestHost.VmId, "web01", Notes.WithIdentity());
    private static readonly VirtualMachine Db01 = new("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "db01", Notes.WithIdentity(assignedId: "db01.prod.example.com", securityTags: "[]"));
    private static readonly VirtualMachine Bare01 = new("bbbbbbbb-cccc-dddd-eeee-ffffffffffff", "bare01", Notes.WithoutIdentity);

    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ServiceProvider services = new ServiceCollection().AddMetrics().BuildServiceProvider();
    private readonly FakeHyperV hyperV = new();
    private readonly ManualTime time = new(DateTimeOffset.UtcNow);
    private readonly HostTokenSigner signer;
    private readonly TokenRefresher refresher;
    private readonly ValidatorHarness issuer;

    public RefresherTests()
    {
        signer = CreateSigner(new RefresherOptions { IssuerUrl = TestHost.IssuerUrl, HostId = "hv-host-01" });
        refresher = new TokenRefresher(hyperV, signer, time, services.GetRequiredService<IMeterFactory>(), NullLogger<TokenRefresher>.Instance);
        issuer = new ValidatorHarness(AllowlistFor(signer, "hv-host-01"));
    }

    public void Dispose()
    {
        issuer.Dispose();
        services.Dispose();
        key.Dispose();
    }

    private HostTokenSigner CreateSigner(RefresherOptions options) => new(key, Options.Create(options));

    private static string AllowlistFor(HostTokenSigner signer, string host) =>
        TestHost.Allowlist(
            $"  - host: {host}\n"
            + "    keys:\n"
            + $"      - kid: {signer.Kid}\n"
            + "        status: active\n"
            + $"        jwk: {{ kty: EC, crv: P-256, x: {signer.Jwk.X}, y: {signer.Jwk.Y} }}\n");

    private static JsonElement Payload(string token) =>
        JsonDocument.Parse(Base64UrlEncoder.Decode(new JsonWebToken(token).EncodedPayload)).RootElement;

    // Signing.

    [Fact]
    public async Task SignedTokenPassesIssuerValidation()
    {
        var signed = signer.Sign(Web01, TestHost.Identity(), DateTimeOffset.UtcNow);

        var result = await issuer.ValidateAsync(signed.Token);

        Assert.True(result.IsValid, result.Failure.ToString());
        Assert.Equal(TestHost.VmId, result.Identity!.VmId);
        Assert.Equal(TestHost.Subject, result.Identity.Subject);
        Assert.Equal(TestHost.Identity(), result.Identity.Identity);
        Assert.Equal("hv-host-01", result.Identity.Host);
        Assert.Equal("web01", result.Identity.VmName);
        Assert.Equal(signed.Jti, result.Identity.Jti);
        Assert.False(signed.VmNameOmitted);
    }

    [Fact]
    public void TokenHasDesignHeaderAndClaims()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var token = signer.Sign(Web01, TestHost.Identity(), now).Token;
        var jwt = new JsonWebToken(token);

        Assert.Equal(ProofAlgorithms.Signing, jwt.Alg);
        Assert.Equal(ProofTokenTypes.HostToken, jwt.Typ);
        Assert.Equal(signer.Kid, jwt.Kid);
        Assert.Equal(ProofKeys.ComputeKid(signer.Jwk), jwt.Kid);
        Assert.Equal("hv-host-01", jwt.Issuer);
        Assert.Equal([TestHost.IssuerUrl], jwt.Audiences);
        Assert.Equal(TestHost.VmId, jwt.Subject);
        Assert.Equal(now, new DateTimeOffset(jwt.IssuedAt));
        Assert.Equal(now, new DateTimeOffset(jwt.ValidFrom));
        Assert.Equal(now + HostTokenPolicy.Lifetime, new DateTimeOffset(jwt.ValidTo));
        Assert.Matches("^[0-9a-f]{32}$", jwt.Id);

        var payload = Payload(token);
        Assert.Equal("acme", payload.GetProperty("tenant").GetString());
        Assert.Equal("web01.prod.example.com", payload.GetProperty("assigned_id").GetString());
        Assert.Equal(["puppet", "ssh-ca"], payload.GetProperty("security_tags").EnumerateArray().Select(e => e.GetString()));
        Assert.False(payload.TryGetProperty("cluster", out _));
    }

    [Fact]
    public void NoSecurityTagsAreSignedAsAnEmptyArray()
    {
        var payload = Payload(signer.Sign(Web01, TestHost.Identity(securityTags: []), DateTimeOffset.UtcNow).Token);

        Assert.Equal(JsonValueKind.Array, payload.GetProperty("security_tags").ValueKind);
        Assert.Equal(0, payload.GetProperty("security_tags").GetArrayLength());
    }

    [Fact]
    public void JtiIsFreshEachTime()
    {
        var now = DateTimeOffset.UtcNow;
        Assert.NotEqual(signer.Sign(Web01, TestHost.Identity(), now).Jti, signer.Sign(Web01, TestHost.Identity(), now).Jti);
    }

    [Fact]
    public void TypicalTokenFitsWellInsideKvpLimit()
    {
        // Measured with a realistic issuer URL and names: about 660 characters, leaving room for longer identities.
        var s = CreateSigner(new RefresherOptions { IssuerUrl = "https://id.corp.example", HostId = "hv-host-01" });
        var token = s.Sign(Web01, TestHost.Identity(), DateTimeOffset.UtcNow).Token;

        Assert.InRange(token.Length, 600, 720);
    }

    [Theory]
    // What the documentation promises: with an issuer URL and host ID of 32 characters each, an identity fits if its
    // tenant, assigned ID and tags, counting 3 more characters per tag, add up to 340 characters. Measured, the limit
    // is 343. The largest tenant and assigned ID always fit together.
    [InlineData(63, 253, new[] { 21 }, true)]
    [InlineData(32, 64, new[] { 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16 }, true)]
    [InlineData(4, 22, new[] { 6, 6 }, true)]
    [InlineData(63, 253, new[] { 28 }, false)]
    [InlineData(32, 64, new[] { 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16 }, false)]
    public void DocumentedIdentityBudgetFits(int tenant, int assignedId, int[] tags, bool fits)
    {
        var s = CreateSigner(new RefresherOptions { IssuerUrl = "https://" + new string('i', 24), HostId = new string('h', 32) });
        var identity = TestHost.Identity(
            new string('t', tenant), new string('a', assignedId), tags.Select((length, i) => $"{i:x}{new string('s', length - 1)}").ToArray());
        Assert.Equal(fits, tenant + assignedId + tags.Sum(t => t + 3) <= 340);

        Assert.Equal(fits, s.Sign(Web01, identity, DateTimeOffset.UtcNow).Fits);
    }

    [Fact]
    public async Task LongVmNameIsLeftOutToFitOneKvpValue()
    {
        // 100 characters is the Hyper-V maximum; non-ASCII names grow when encoded.
        var vm = Web01 with { Name = new string('é', 100) + new string('漢', 100) };

        var signed = signer.Sign(vm, TestHost.Identity(), DateTimeOffset.UtcNow);

        Assert.True(signed.VmNameOmitted);
        Assert.True(signed.Fits);
        Assert.False(new JsonWebToken(signed.Token).TryGetClaim(ProofClaimNames.VmName, out _));
        Assert.True((await issuer.ValidateAsync(signed.Token)).IsValid);
    }

    [Fact]
    public void MaximumLengthAsciiVmNameStillFits()
    {
        var signed = signer.Sign(Web01 with { Name = new string('w', 100) }, TestHost.Identity(), DateTimeOffset.UtcNow);

        Assert.False(signed.VmNameOmitted);
        Assert.True(signed.Fits);
    }

    [Fact]
    public void LargestIdentityDoesNotFitAndIsNotShortened()
    {
        var identity = TestHost.Identity(
            new string('t', VmIdentity.MaxTenantLength),
            new string('a', VmIdentity.MaxAssignedIdLength),
            Enumerable.Range(0, VmIdentity.MaxSecurityTags).Select(i => $"{i:x}{new string('s', VmIdentity.MaxSecurityTagLength - 1)}").ToArray());

        var signed = signer.Sign(Web01, identity, DateTimeOffset.UtcNow);

        Assert.False(signed.Fits);
        Assert.True(signed.VmNameOmitted);
        Assert.Equal(VmIdentity.MaxSecurityTags, Payload(signed.Token).GetProperty("security_tags").GetArrayLength());
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
        var other = CreateSigner(new RefresherOptions { IssuerUrl = TestHost.IssuerUrl, HostId = "hv-host-02" });

        var result = await issuer.ValidateAsync(other.Sign(Web01, TestHost.Identity(), DateTimeOffset.UtcNow).Token);

        Assert.Equal(HostTokenFailure.ValidationFailed, result.Failure);
    }

    // Refresh loop.

    [Fact]
    public async Task FirstPassWritesEveryVmWithAnIdentity()
    {
        hyperV.Running.AddRange([Web01, Db01]);

        var pass = await refresher.RefreshAsync(CancellationToken.None);

        Assert.Equal((2, 2, 0), (pass.Running, pass.Written, pass.Failed));
        foreach (var (vm, subject) in new[] { (Web01, TestHost.Subject), (Db01, $"tenant:acme:assignedID:db01.prod.example.com:vmID:{Db01.Id}") })
        {
            var result = await issuer.ValidateAsync(hyperV.Token(vm)!);
            Assert.True(result.IsValid, result.Failure.ToString());
            Assert.Equal(subject, result.Identity!.Subject);
            Assert.Equal(vm.Name, result.Identity.VmName);
        }
    }

    [Fact]
    public async Task TenantAndAssignedIdAreLowercased()
    {
        hyperV.Running.Add(Web01 with { Notes = Notes.WithIdentity("ACME", "Web01.Prod.Example.COM") });

        await refresher.RefreshAsync(CancellationToken.None);

        Assert.Equal(TestHost.Subject, (await issuer.ValidateAsync(hyperV.Token(Web01)!)).Identity!.Subject);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Just notes, no block.")]
    [InlineData(Notes.WithoutIdentity)]
    public async Task VmWithoutIdentityGetsNoTokenAndLosesAnOldOne(string? notes)
    {
        // A token from before, or from another host before the VM migrated here.
        var vm = Bare01 with { Notes = notes };
        hyperV.Kvp[vm.Id] = new() { [KvpKeys.Token] = "old" };
        hyperV.Running.Add(vm);

        var pass = await refresher.RefreshAsync(CancellationToken.None);

        Assert.Equal(VmTokenOutcome.NotEnrolled, Assert.Single(pass.Results).Outcome);
        Assert.False(hyperV.HasToken(vm));
        Assert.Equal(0, hyperV.Writes);
    }

    [Fact]
    public async Task TokenIsRemovedOnceNotOnEveryPass()
    {
        hyperV.Running.Add(Bare01);
        await refresher.RefreshAsync(CancellationToken.None);

        time.Advance(HostTokenPolicy.RefreshInterval);
        var pass = await refresher.RefreshAsync(CancellationToken.None);

        Assert.Empty(pass.Results);
        Assert.Equal(1, hyperV.Removals);
        Assert.Equal(VmTokenOutcome.NotEnrolled, Assert.Single((await refresher.RefreshAsync(CancellationToken.None, force: true)).Results).Outcome);
    }

    [Theory]
    [InlineData("Bad:Tenant", TestHost.AssignedId, "[]", "tenant must be")]
    [InlineData(TestHost.Tenant, "web 01", "[]", "assigned-id must be")]
    [InlineData(TestHost.Tenant, TestHost.AssignedId, "[Puppet]", "security-tags[0] must be")]
    [InlineData(TestHost.Tenant, TestHost.AssignedId, "[a, a]", "repeats")]
    [InlineData(TestHost.Tenant, TestHost.AssignedId, "puppet", "must be a list")]
    public async Task InvalidIdentityIsRefusedWithAReasonThatQuotesNoValue(string tenant, string assignedId, string tags, string reason)
    {
        var vm = Web01 with { Notes = Notes.WithIdentity(tenant, assignedId, tags) };
        hyperV.Kvp[vm.Id] = new() { [KvpKeys.Token] = "old" };
        hyperV.Running.Add(vm);

        var pass = await refresher.RefreshAsync(CancellationToken.None);

        var result = Assert.Single(pass.Results);
        Assert.Equal(VmTokenOutcome.Refused, result.Outcome);
        Assert.Contains(reason, result.Detail);
        Assert.DoesNotContain("Bad", result.Detail);
        Assert.DoesNotContain("web 01", result.Detail);
        Assert.Equal(1, pass.Refused);
        Assert.False(hyperV.HasToken(vm));
    }

    [Fact]
    public async Task ABlockThatCannotBeUsedForAnyReasonGivesNoToken()
    {
        // The identity is fine, but the block holding it is not, so none of it is trusted.
        var vm = Web01 with { Notes = Notes.WithIdentity().Replace("  hostname: web01", "  hostname: !sensitivee web01") };
        hyperV.Running.Add(vm);

        var result = Assert.Single((await refresher.RefreshAsync(CancellationToken.None)).Results);

        Assert.Equal(VmTokenOutcome.Refused, result.Outcome);
        Assert.Contains("Unknown tag", result.Detail);
    }

    [Fact]
    public async Task TokenThatDoesNotFitIsNotWrittenAndAnOldOneIsRemoved()
    {
        hyperV.Running.Add(Web01);
        await refresher.RefreshAsync(CancellationToken.None);
        var tags = string.Join(", ", Enumerable.Range(0, 16).Select(i => $"{i:x}{new string('s', 62)}"));
        hyperV.SetNotes(Web01, Notes.WithIdentity(securityTags: $"[{tags}]"));

        var result = Assert.Single((await refresher.RefreshAsync(CancellationToken.None)).Results);

        Assert.Equal(VmTokenOutcome.Refused, result.Outcome);
        Assert.Contains("over the 1023-character KVP limit", result.Detail);
        Assert.False(hyperV.HasToken(Web01));
        Assert.Equal(1, hyperV.Writes);
    }

    [Fact]
    public async Task IdentityChangeIsWrittenAtOnceThoughTheTokenIsNotDue()
    {
        hyperV.Running.Add(Web01);
        await refresher.RefreshAsync(CancellationToken.None);
        var changed = hyperV.SetNotes(Web01, Notes.WithIdentity(securityTags: "[puppet]"));
        time.Advance(TimeSpan.FromSeconds(5));

        Assert.True(refresher.IdentityChanged(changed));
        var result = Assert.Single((await refresher.RefreshAsync(CancellationToken.None)).Results);

        Assert.Equal(VmTokenOutcome.Written, result.Outcome);
        Assert.Equal(["puppet"], (await issuer.ValidateAsync(hyperV.Token(Web01)!)).Identity!.Identity.SecurityTags);
        Assert.False(refresher.IdentityChanged(changed));
    }

    [Fact]
    public async Task IdentityRemovedWhileRunningTakesTheTokenAway()
    {
        hyperV.Running.Add(Web01);
        await refresher.RefreshAsync(CancellationToken.None);
        var changed = hyperV.SetNotes(Web01, Notes.WithoutIdentity);

        Assert.True(refresher.IdentityChanged(changed));
        Assert.Equal(VmTokenOutcome.NotEnrolled, Assert.Single((await refresher.RefreshAsync(CancellationToken.None)).Results).Outcome);
        Assert.False(hyperV.HasToken(Web01));
    }

    [Fact]
    public async Task IdentityAddedWhileRunningIsWrittenAtOnce()
    {
        hyperV.Running.Add(Bare01);
        await refresher.RefreshAsync(CancellationToken.None);
        var changed = hyperV.SetNotes(Bare01, Notes.WithIdentity(assignedId: "bare01"));

        Assert.True(refresher.IdentityChanged(changed));
        Assert.Equal(VmTokenOutcome.Written, Assert.Single((await refresher.RefreshAsync(CancellationToken.None)).Results).Outcome);
    }

    [Fact]
    public async Task NotesChangesThatKeepTheIdentityChangeNothing()
    {
        hyperV.Running.Add(Web01);
        await refresher.RefreshAsync(CancellationToken.None);

        // What the metadata service does when provisioning finishes, and an operator editing their own notes.
        var changed = hyperV.SetNotes(Web01, "Moved to the platform team.\r\n" + Notes.WithIdentity()[(Notes.WithIdentity().IndexOf('#'))..]
            .Replace("#proof-metadata-end", "provisioning: { status: complete, at: \"2026-01-01T00:00:00Z\", instance-id: x }\r\n#proof-metadata-end"));

        Assert.False(refresher.IdentityChanged(changed));
        Assert.Empty((await refresher.RefreshAsync(CancellationToken.None)).Results);
    }

    [Fact]
    public void IdentityChangedIsFalseForAVmNoPassHasSeen() =>
        Assert.False(refresher.IdentityChanged(Web01));

    [Fact]
    public async Task IdentityChangedSeesABrokenOrRepairedBlock()
    {
        hyperV.Running.Add(Web01);
        await refresher.RefreshAsync(CancellationToken.None);
        var broken = hyperV.SetNotes(Web01, Notes.WithIdentity(tenant: "a:b"));

        Assert.True(refresher.IdentityChanged(broken));
        await refresher.RefreshAsync(CancellationToken.None);
        Assert.False(refresher.IdentityChanged(broken));
        Assert.True(refresher.IdentityChanged(broken with { Notes = Notes.WithIdentity() }));
    }

    [Fact]
    public async Task RewritesOnlyNearRefreshInterval()
    {
        hyperV.Running.Add(Web01);
        await refresher.RefreshAsync(CancellationToken.None);
        var first = hyperV.Token(Web01);

        time.Advance(HostTokenPolicy.RefreshInterval - TokenRefresher.RenewalSlack - TimeSpan.FromSeconds(1));
        Assert.Equal(0, (await refresher.RefreshAsync(CancellationToken.None)).Written);
        Assert.Equal(first, hyperV.Token(Web01));

        time.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(1, (await refresher.RefreshAsync(CancellationToken.None)).Written);
        Assert.NotEqual(first, hyperV.Token(Web01));
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
        Assert.Contains("32768", pass.Results.Single(r => r.Vm == Web01).Detail);
        Assert.True(hyperV.HasToken(Db01));

        hyperV.Failing.Clear();
        time.Advance(TimeSpan.FromSeconds(30));
        pass = await refresher.RefreshAsync(CancellationToken.None);
        Assert.Equal([Web01], pass.Results.Select(r => r.Vm));
        Assert.Equal(0, pass.Failed);
    }

    [Fact]
    public async Task FailedRemovalIsRetriedNextPass()
    {
        hyperV.Kvp[Bare01.Id] = new() { [KvpKeys.Token] = "old" };
        hyperV.Running.Add(Bare01);
        hyperV.Failing.Add(Bare01.Id);

        Assert.Equal(VmTokenOutcome.Failed, Assert.Single((await refresher.RefreshAsync(CancellationToken.None)).Results).Outcome);
        Assert.True(hyperV.HasToken(Bare01));

        hyperV.Failing.Clear();
        Assert.Equal(VmTokenOutcome.NotEnrolled, Assert.Single((await refresher.RefreshAsync(CancellationToken.None)).Results).Outcome);
        Assert.False(hyperV.HasToken(Bare01));
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
    public async Task OldestTokenAgeTracksFailingVmAndIgnoresVmsWithoutIdentity()
    {
        hyperV.Running.AddRange([Web01, Db01, Bare01]);
        await refresher.RefreshAsync(CancellationToken.None);

        hyperV.Failing.Add(Web01.Id);
        time.Advance(HostTokenPolicy.RefreshInterval);
        await refresher.RefreshAsync(CancellationToken.None);
        time.Advance(TimeSpan.FromMinutes(1));

        Assert.Equal(HostTokenPolicy.RefreshInterval + TimeSpan.FromMinutes(1), refresher.OldestTokenAge());
    }

    [Fact]
    public async Task GaugesCountVmsByWhatTheirNotesSay()
    {
        hyperV.Running.AddRange([Web01, Db01, Bare01, Web01 with { Id = Guid.NewGuid().ToString("D"), Notes = Notes.WithIdentity(tenant: "-") }]);
        await refresher.RefreshAsync(CancellationToken.None);

        var gauges = new Dictionary<string, double>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            // Only this test's meter: other tests running at the same time have refreshers of their own.
            if (instrument.Meter.Name == TokenRefresher.MeterName && instrument.Meter.Scope == services.GetRequiredService<IMeterFactory>())
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<double>((instrument, value, _, _) => gauges[instrument.Name] = value);
        listener.SetMeasurementEventCallback<int>((instrument, value, _, _) => gauges[instrument.Name] = value);
        listener.Start();
        listener.RecordObservableInstruments();

        Assert.Equal(4, gauges["proof.refresher.running_vms"]);
        Assert.Equal(2, gauges["proof.refresher.enrolled_vms"]);
        Assert.Equal(1, gauges["proof.refresher.identity_errors"]);
    }

    // Options.

    [Theory]
    [InlineData("https://proof.test", "hv-host-01", true)]
    [InlineData("http://proof.test", "hv-host-01", false)]
    [InlineData("https://proof.test/", "hv-host-01", false)]
    [InlineData("https://proof.test", "", false)]
    [InlineData("https://proof.test", "hv host", false)]
    [InlineData("https://proof.test", "hv-host-01: x", false)]
    [InlineData("https://proof.test", "hv-host-01\n", false)]
    public void ValidatesOptions(string issuerUrl, string hostId, bool valid)
    {
        var result = new RefresherOptionsValidator().Validate(null, new RefresherOptions { IssuerUrl = issuerUrl, HostId = hostId });

        Assert.Equal(valid, result.Succeeded);
    }

    [Fact]
    public void ScanIntervalMustNotExceedRefreshInterval()
    {
        var options = new RefresherOptions { IssuerUrl = TestHost.IssuerUrl, ScanInterval = HostTokenPolicy.RefreshInterval + TimeSpan.FromSeconds(1) };

        Assert.False(new RefresherOptionsValidator().Validate(null, options).Succeeded);
    }
}
