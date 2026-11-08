using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Proof.Issuer;
using Proof.Shared;
using Proof.Tests.Support;

namespace Proof.Tests;

/// <summary>Negative tests for host tokens. Each bad token must be refused.</summary>
public sealed class HostTokenValidatorTests : IDisposable
{
    private readonly TestHost host = new();
    private readonly ValidatorHarness harness;

    public HostTokenValidatorTests()
    {
        harness = new ValidatorHarness(TestHost.Allowlist(host.AllowlistEntry()));
    }

    public void Dispose() => harness.Dispose();

    private async Task AssertRefused(string token, HostTokenFailure expected)
    {
        var result = await harness.ValidateAsync(token);
        Assert.False(result.IsValid);
        Assert.Equal(expected, result.Failure);
    }

    private static long Now => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    [Fact]
    public async Task AcceptsWellFormedToken()
    {
        var result = await harness.ValidateAsync(host.CreateToken());

        Assert.True(result.IsValid, result.Failure.ToString());
        var identity = result.Identity!;
        Assert.Equal("tenant:acme:assignedID:web01.prod.example.com:vmID:" + TestHost.VmId, identity.Subject);
        Assert.Equal(TestHost.VmId, identity.VmId);
        Assert.Equal(TestHost.Identity(), identity.Identity);
        Assert.Equal(host.HostId, identity.Host);
        Assert.Equal(host.Kid, identity.Kid);
        Assert.Equal("web01", identity.VmName);
    }

    [Fact]
    public async Task AcceptsTokenWithoutOptionalClaims()
    {
        var token = host.CreateToken(c =>
        {
            c.Remove(ProofClaimNames.VmName);
            c[ProofClaimNames.SecurityTags] = Array.Empty<string>();
        });

        var result = await harness.ValidateAsync(token);
        Assert.True(result.IsValid, result.Failure.ToString());
        Assert.Empty(result.Identity!.Identity.SecurityTags);
        Assert.Null(result.Identity.VmName);
    }

    // Lifetime and clock skew.

    [Fact]
    public Task RefusesExpiredToken() =>
        AssertRefused(host.CreateToken(c =>
        {
            c[JwtRegisteredClaimNames.Iat] = Now - 3600;
            c[JwtRegisteredClaimNames.Nbf] = Now - 3600;
            c[JwtRegisteredClaimNames.Exp] = Now - 600;
        }), HostTokenFailure.ValidationFailed);

    [Fact]
    public Task RefusesNotYetValidToken() =>
        AssertRefused(host.CreateToken(c => c[JwtRegisteredClaimNames.Nbf] = Now + 600), HostTokenFailure.ValidationFailed);

    [Fact]
    public async Task AcceptsExpiryJustInsideSkew()
    {
        var token = host.CreateToken(c =>
        {
            c[JwtRegisteredClaimNames.Iat] = Now - 1200;
            c[JwtRegisteredClaimNames.Nbf] = Now - 1200;
            c[JwtRegisteredClaimNames.Exp] = Now - 110;
        });

        Assert.True((await harness.ValidateAsync(token)).IsValid);
    }

    [Fact]
    public Task RefusesExpiryJustOutsideSkew() =>
        AssertRefused(host.CreateToken(c =>
        {
            c[JwtRegisteredClaimNames.Iat] = Now - 1200;
            c[JwtRegisteredClaimNames.Nbf] = Now - 1200;
            c[JwtRegisteredClaimNames.Exp] = Now - 130;
        }), HostTokenFailure.ValidationFailed);

    [Fact]
    public async Task AcceptsNotBeforeJustInsideSkew()
    {
        var token = host.CreateToken(c =>
        {
            c[JwtRegisteredClaimNames.Iat] = Now + 110;
            c[JwtRegisteredClaimNames.Nbf] = Now + 110;
        });

        Assert.True((await harness.ValidateAsync(token)).IsValid);
    }

    [Fact]
    public Task RefusesNotBeforeJustOutsideSkew() =>
        AssertRefused(host.CreateToken(c =>
        {
            c[JwtRegisteredClaimNames.Iat] = Now;
            c[JwtRegisteredClaimNames.Nbf] = Now + 130;
        }), HostTokenFailure.ValidationFailed);

    [Fact]
    public Task RefusesLifetimeAboveCap() =>
        AssertRefused(host.CreateToken(c => c[JwtRegisteredClaimNames.Exp] = Now + (long)HostTokenPolicy.MaxLifetime.TotalSeconds + 60),
            HostTokenFailure.LifetimeTooLong);

    [Fact]
    public Task RefusesIssuedAtInFuture() =>
        AssertRefused(host.CreateToken(c => c[JwtRegisteredClaimNames.Iat] = Now + 600), HostTokenFailure.IssuedInFuture);

    // Claims.

    [Fact]
    public Task RefusesWrongAudience() =>
        AssertRefused(host.CreateToken(c => c[JwtRegisteredClaimNames.Aud] = "https://other.test"), HostTokenFailure.ValidationFailed);

    [Fact]
    public Task RefusesAudienceWithTrailingSlash() =>
        AssertRefused(host.CreateToken(c => c[JwtRegisteredClaimNames.Aud] = TestHost.IssuerUrl + "/"), HostTokenFailure.ValidationFailed);

    [Fact]
    public Task RefusesExtraAudience() =>
        AssertRefused(host.CreateToken(c => c[JwtRegisteredClaimNames.Aud] = new[] { TestHost.IssuerUrl, "https://other.test" }),
            HostTokenFailure.InvalidClaim);

    [Fact]
    public Task RefusesIssuerOtherThanHostForKid() =>
        AssertRefused(host.CreateToken(c => c[JwtRegisteredClaimNames.Iss] = "hv-host-02"), HostTokenFailure.ValidationFailed);

    [Theory]
    [InlineData(JwtRegisteredClaimNames.Iss, HostTokenFailure.ValidationFailed)]
    [InlineData(JwtRegisteredClaimNames.Aud, HostTokenFailure.ValidationFailed)]
    [InlineData(JwtRegisteredClaimNames.Exp, HostTokenFailure.ValidationFailed)]
    [InlineData(JwtRegisteredClaimNames.Sub, HostTokenFailure.InvalidSubject)]
    [InlineData(JwtRegisteredClaimNames.Iat, HostTokenFailure.InvalidClaim)]
    [InlineData(JwtRegisteredClaimNames.Nbf, HostTokenFailure.InvalidClaim)]
    [InlineData(JwtRegisteredClaimNames.Jti, HostTokenFailure.InvalidClaim)]
    public Task RefusesMissingRequiredClaim(string claim, HostTokenFailure expected) =>
        AssertRefused(host.CreateToken(c => c.Remove(claim)), expected);

    [Theory]
    [InlineData("web01")]
    [InlineData("11111111-2222-3333-4444-55555555555")]
    [InlineData("11111111-2222-3333-4444-AAAAAAAAAAAA")]
    [InlineData("{11111111-2222-3333-4444-555555555555}")]
    [InlineData("11111111222233334444555555555555")]
    public Task RefusesNonCanonicalSubject(string sub) =>
        AssertRefused(host.CreateToken(c => c[JwtRegisteredClaimNames.Sub] = sub), HostTokenFailure.InvalidSubject);

    // Identity.

    [Theory]
    [InlineData(ProofClaimNames.Tenant)]
    [InlineData(ProofClaimNames.AssignedId)]
    public Task RefusesTokenWithoutIdentity(string claim) =>
        AssertRefused(host.CreateToken(c => c.Remove(claim)), HostTokenFailure.MissingIdentity);

    [Fact]
    public Task RefusesTokenWithoutSecurityTags() =>
        AssertRefused(host.CreateToken(c => c.Remove(ProofClaimNames.SecurityTags)), HostTokenFailure.InvalidIdentity);

    [Theory]
    [InlineData("ACME")]
    [InlineData("acme:corp")]
    [InlineData("-acme")]
    [InlineData("acme corp")]
    [InlineData("acme\n")]
    [InlineData("")]
    [InlineData("acmé")]
    public Task RefusesNonCanonicalTenant(string tenant) =>
        AssertRefused(host.CreateToken(c => c[ProofClaimNames.Tenant] = tenant), HostTokenFailure.InvalidIdentity);

    [Theory]
    [InlineData("Web01.prod.example.com")]
    [InlineData("web01:prod")]
    [InlineData(".web01")]
    [InlineData("web01/prod")]
    public Task RefusesNonCanonicalAssignedId(string assignedId) =>
        AssertRefused(host.CreateToken(c => c[ProofClaimNames.AssignedId] = assignedId), HostTokenFailure.InvalidIdentity);

    [Fact]
    public async Task HoldsValuesToTheirLengthLimits()
    {
        Assert.True((await harness.ValidateAsync(host.CreateToken(c => c[ProofClaimNames.Tenant] = new string('t', 63)))).IsValid);
        await AssertRefused(host.CreateToken(c => c[ProofClaimNames.Tenant] = new string('t', 64)), HostTokenFailure.InvalidIdentity);
        Assert.True((await harness.ValidateAsync(host.CreateToken(c => c[ProofClaimNames.AssignedId] = new string('a', 253)))).IsValid);
        await AssertRefused(host.CreateToken(c => c[ProofClaimNames.AssignedId] = new string('a', 254)), HostTokenFailure.InvalidIdentity);
    }

    public static TheoryData<object> BadSecurityTags() => new()
    {
        "puppet",
        new[] { "puppet", "puppet" },
        new[] { "Puppet" },
        new[] { "ssh:ca" },
        new[] { "" },
        new object[] { "puppet", 7 },
        Enumerable.Range(0, 17).Select(i => $"tag{i}").ToArray(),
        new[] { new string('t', 64) },
    };

    [Theory]
    [MemberData(nameof(BadSecurityTags))]
    public Task RefusesBadSecurityTags(object tags) =>
        AssertRefused(host.CreateToken(c => c[ProofClaimNames.SecurityTags] = tags), HostTokenFailure.InvalidIdentity);

    [Fact]
    public async Task AcceptsSixteenSecurityTags()
    {
        var tags = Enumerable.Range(0, 16).Select(i => $"tag{i}").ToArray();
        var result = await harness.ValidateAsync(host.CreateToken(c => c[ProofClaimNames.SecurityTags] = tags));
        Assert.True(result.IsValid, result.Failure.ToString());
        Assert.Equal(tags, result.Identity!.Identity.SecurityTags);
    }

    [Theory]
    [InlineData(ProofClaimNames.Tenant)]
    [InlineData(ProofClaimNames.AssignedId)]
    public Task RefusesNonStringIdentity(string claim) =>
        AssertRefused(host.CreateToken(c => c[claim] = 7), HostTokenFailure.InvalidIdentity);

    [Fact]
    public async Task IgnoresAClusterFromAnOlderHost()
    {
        var result = await harness.ValidateAsync(host.CreateToken(c => c["cluster"] = "prod"));

        Assert.True(result.IsValid, result.Failure.ToString());
        Assert.Equal(TestHost.Subject, result.Identity!.Subject);
    }

    // Header and algorithm.

    [Fact]
    public Task RefusesWrongType() =>
        AssertRefused(host.CreateToken(typ: "JWT"), HostTokenFailure.WrongType);

    [Fact]
    public Task RefusesAlgNone()
    {
        // IdentityModel will not put a kid on an unsigned token, so assemble this one by hand.
        var header = Base64UrlEncoder.Encode($$"""{"alg":"none","typ":"{{ProofTokenTypes.HostToken}}","kid":"{{host.Kid}}"}""");
        var payload = host.CreateToken().Split('.')[1];
        return AssertRefused($"{header}.{payload}.", HostTokenFailure.DisallowedAlgorithm);
    }

    [Fact]
    public Task RefusesHs256SignedWithThePublicKey()
    {
        var secret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes($"{host.Jwk.X}.{host.Jwk.Y}")) { KeyId = host.Kid };
        var token = TestHost.Sign(host.DefaultClaims(), new SigningCredentials(secret, SecurityAlgorithms.HmacSha256), ProofTokenTypes.HostToken);
        return AssertRefused(token, HostTokenFailure.DisallowedAlgorithm);
    }

    [Fact]
    public Task RefusesRs256()
    {
        using var rsa = RSA.Create(2048);
        var credentials = new SigningCredentials(new RsaSecurityKey(rsa) { KeyId = host.Kid }, SecurityAlgorithms.RsaSha256);
        return AssertRefused(TestHost.Sign(host.DefaultClaims(), credentials, ProofTokenTypes.HostToken), HostTokenFailure.DisallowedAlgorithm);
    }

    [Fact]
    public Task RefusesEncryptedToken()
    {
        var handler = new JsonWebTokenHandler();
        var token = handler.CreateToken(new SecurityTokenDescriptor
        {
            TokenType = ProofTokenTypes.HostToken,
            Claims = host.DefaultClaims(),
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(host.Key) { KeyId = host.Kid }, ProofAlgorithms.Signing),
            EncryptingCredentials = new EncryptingCredentials(
                new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)),
                SecurityAlgorithms.Aes256KW,
                SecurityAlgorithms.Aes128CbcHmacSha256),
        });
        return AssertRefused(token, HostTokenFailure.Encrypted);
    }

    // Keys and signatures.

    [Fact]
    public Task RefusesUnknownKid()
    {
        var stranger = new TestHost(host.HostId);
        return AssertRefused(stranger.CreateToken(), HostTokenFailure.UnknownKey);
    }

    [Fact]
    public Task RefusesMissingKid() =>
        AssertRefused(host.CreateToken(kid: ""), HostTokenFailure.UnknownKey);

    [Fact]
    public Task RefusesKnownKidWithSignatureFromAnotherKey()
    {
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return AssertRefused(host.CreateToken(signWith: other, kid: host.Kid), HostTokenFailure.ValidationFailed);
    }

    [Fact]
    public Task RefusesTamperedPayload()
    {
        var parts = host.CreateToken().Split('.');
        var payload = Base64UrlEncoder.Decode(parts[1]).Replace(TestHost.VmId, "99999999-2222-3333-4444-555555555555");
        return AssertRefused($"{parts[0]}.{Base64UrlEncoder.Encode(payload)}.{parts[2]}", HostTokenFailure.ValidationFailed);
    }

    [Fact]
    public Task RefusesTokenOverSizeLimit() =>
        AssertRefused(host.CreateToken(c => c["padding"] = new string('a', HostTokenPolicy.MaxEncodedLength)), HostTokenFailure.TooLarge);

    [Theory]
    [InlineData("")]
    [InlineData("not a token")]
    [InlineData("a.b.c")]
    [InlineData("eyJhbGciOiJFUzI1NiJ9.e30")]
    public Task RefusesMalformedToken(string token) =>
        AssertRefused(token, HostTokenFailure.Malformed);

    // Allowlist.

    [Fact]
    public async Task RefusesKeyRemovedFromAllowlist()
    {
        var other = new TestHost("hv-host-02");
        harness.WriteAllowlist(TestHost.Allowlist(other.AllowlistEntry()));

        await AssertRefused(host.CreateToken(), HostTokenFailure.UnknownKey);
        Assert.True((await harness.ValidateAsync(other.CreateToken())).IsValid);
    }

    [Fact]
    public async Task KeepsPreviousListWhenNewFileIsInvalid()
    {
        harness.WriteAllowlist("version: 1\nhosts: [ this is not right");

        Assert.False(harness.Monitor.LastReadSucceeded);
        Assert.True((await harness.ValidateAsync(host.CreateToken())).IsValid);
    }

    [Fact]
    public async Task AcceptsRetiredKeyBeforeNotAfter()
    {
        harness.WriteAllowlist(TestHost.Allowlist(host.AllowlistEntry("retired", DateTime.UtcNow.AddDays(1).ToString("yyyy-MM-dd"))));
        Assert.True((await harness.ValidateAsync(host.CreateToken())).IsValid);
    }

    [Fact]
    public async Task IgnoresRetiredKeyAfterNotAfter()
    {
        harness.WriteAllowlist(TestHost.Allowlist(host.AllowlistEntry("retired", DateTime.UtcNow.AddDays(-1).ToString("yyyy-MM-dd"))));
        await AssertRefused(host.CreateToken(), HostTokenFailure.UnknownKey);
    }

    [Fact]
    public async Task IgnoresActiveKeyAfterNotAfter()
    {
        harness.WriteAllowlist(TestHost.Allowlist(host.AllowlistEntry("active", DateTime.UtcNow.AddDays(-1).ToString("yyyy-MM-dd"))));
        await AssertRefused(host.CreateToken(), HostTokenFailure.UnknownKey);
    }

    [Fact]
    public async Task RefusesEverythingBeforeAnAllowlistLoads()
    {
        using var empty = new ValidatorHarness("not: [valid");
        var result = await empty.ValidateAsync(host.CreateToken());
        Assert.Equal(HostTokenFailure.AllowlistNotLoaded, result.Failure);
    }

    // Subjects. The host that signed is not part of the subject: every allowlisted host is one trust environment.

    [Fact]
    public async Task GivesAVmTheSameSubjectFromEveryHost()
    {
        // Live migration moves a VM between hosts, and its notes go with it; its identity must not change.
        var first = new TestHost("hv-host-01");
        var second = new TestHost("hv-host-02");
        using var both = new ValidatorHarness(TestHost.Allowlist(first.AllowlistEntry(), second.AllowlistEntry()));

        Assert.Equal(TestHost.Subject, (await both.ValidateAsync(first.CreateToken())).Identity!.Subject);
        Assert.Equal(TestHost.Subject, (await both.ValidateAsync(second.CreateToken())).Identity!.Subject);
    }

    [Fact]
    public async Task GivesVmsWithOneTenantAndAssignedIdDifferentSubjects()
    {
        // Proof does not enforce unique (tenant, assigned ID) pairs; the VM ID keeps the subjects apart.
        const string other = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

        var subject = (await harness.ValidateAsync(host.CreateToken(c => c[JwtRegisteredClaimNames.Sub] = other))).Identity!.Subject;

        Assert.Equal($"tenant:{TestHost.Tenant}:assignedID:{TestHost.AssignedId}:vmID:{other}", subject);
        Assert.NotEqual(TestHost.Subject, subject);
    }
}
