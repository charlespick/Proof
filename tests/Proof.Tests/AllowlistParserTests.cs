using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Proof.Issuer.Allowlist;
using Proof.Tests.Support;

namespace Proof.Tests;

public sealed class AllowlistParserTests
{
    private readonly TestHost host = new();

    private static HostAllowlist Parse(string yaml) => AllowlistParser.Parse(Encoding.UTF8.GetBytes(yaml));

    private static void AssertRefused(string yaml, string messageFragment)
    {
        var ex = Assert.Throws<AllowlistException>(() => Parse(yaml));
        Assert.Contains(messageFragment, ex.Message);
    }

    [Fact]
    public void ParsesDesignExampleShape()
    {
        var list = Parse(TestHost.Allowlist(host.AllowlistEntry("active", "2027-06-30")));

        var key = Assert.Single(list.Keys.Values);
        Assert.Equal(host.Kid, key.Kid);
        Assert.Equal("hv-host-01", key.Host);
        Assert.Equal("prod", key.Cluster);
        Assert.Equal(HostKeyStatus.Active, key.Status);
        Assert.Equal(new DateTimeOffset(2027, 7, 1, 0, 0, 0, TimeSpan.Zero), key.NotAfter);
        Assert.Equal(64, list.Sha256.Length);
    }

    [Fact]
    public void NotAfterCoversTheWholeDay()
    {
        var key = Parse(TestHost.Allowlist(host.AllowlistEntry("retired", "2027-06-30"))).Keys[host.Kid];

        Assert.True(key.IsUsableAt(new DateTimeOffset(2027, 6, 30, 23, 59, 59, TimeSpan.Zero)));
        Assert.False(key.IsUsableAt(new DateTimeOffset(2027, 7, 1, 0, 0, 0, TimeSpan.Zero)));
    }

    [Fact]
    public void RefusesKidThatIsNotTheThumbprint() =>
        AssertRefused(TestHost.Allowlist(host.AllowlistEntry()).Replace($"kid: {host.Kid}", "kid: pasted-wrong"), "does not match the JWK thumbprint");

    [Fact]
    public void RefusesPrivateKey()
    {
        var d = Base64UrlEncoder.Encode(host.Key.ExportParameters(true).D);
        AssertRefused(TestHost.Allowlist(host.AllowlistEntry()).Replace("crv: P-256,", $"crv: P-256, d: {d},"), "private key");
    }

    [Fact]
    public void RefusesUnknownJwkMember() =>
        AssertRefused(TestHost.Allowlist(host.AllowlistEntry()).Replace("crv: P-256,", "crv: P-256, use: sig,"), "unexpected member 'use'");

    [Fact]
    public void RefusesUnknownField() =>
        AssertRefused(TestHost.Allowlist(host.AllowlistEntry()).Replace("    keys:", "    region: west\n    keys:"), "not valid YAML for this schema");

    [Fact]
    public void RefusesOtherCurve() =>
        AssertRefused(TestHost.Allowlist(host.AllowlistEntry()).Replace("crv: P-256", "crv: P-384"), "crv P-256");

    [Fact]
    public void RefusesPointNotOnCurve()
    {
        var q = host.Key.ExportParameters(false).Q;
        var y = (byte[])q.Y!.Clone();
        y[^1] ^= 1;
        var badY = Base64UrlEncoder.Encode(y);
        var jwk = new JsonWebKey { Kty = "EC", Crv = "P-256", X = host.Jwk.X, Y = badY };
        var kid = Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());

        var yaml = TestHost.Allowlist(host.AllowlistEntry())
            .Replace($"y: {host.Jwk.Y}", $"y: {badY}")
            .Replace($"kid: {host.Kid}", $"kid: {kid}");

        AssertRefused(yaml, "not a valid P-256 public key");
    }

    [Fact]
    public void RefusesRetiredKeyWithoutNotAfter() =>
        AssertRefused(TestHost.Allowlist(host.AllowlistEntry("retired")), "needs not_after");

    [Theory]
    [InlineData("revoked")]
    [InlineData("Active")]
    public void RefusesUnknownStatus(string status) =>
        AssertRefused(TestHost.Allowlist(host.AllowlistEntry(status)), "status must be");

    [Theory]
    [InlineData("2027-6-30")]
    [InlineData("30/06/2027")]
    [InlineData("2027-06-30T00:00:00Z")]
    public void RefusesMalformedNotAfter(string notAfter) =>
        AssertRefused(TestHost.Allowlist(host.AllowlistEntry("active", notAfter)), "not_after must be a date");

    [Fact]
    public void RefusesDuplicateHost() =>
        AssertRefused(TestHost.Allowlist(host.AllowlistEntry(), new TestHost().AllowlistEntry()), "listed more than once");

    [Fact]
    public void RefusesSameKeyUnderTwoHosts()
    {
        var copy = host.AllowlistEntry().Replace("host: hv-host-01", "host: hv-host-02");
        AssertRefused(TestHost.Allowlist(host.AllowlistEntry(), copy), $"Key '{host.Kid}' is listed more than once");
    }

    [Theory]
    [InlineData("hv/host-01")]
    [InlineData("host:hv-01")]
    [InlineData("-hv-host-01")]
    [InlineData("hv host 01")]
    public void RefusesHostNamesASubjectCannotHold(string name) =>
        AssertRefused(TestHost.Allowlist(host.AllowlistEntry()).Replace("host: hv-host-01", $"host: \"{name}\""), "must be 1 to 253 letters");

    [Theory]
    [InlineData("prod/east")]
    [InlineData("cluster:prod")]
    public void RefusesClusterNamesASubjectCannotHold(string name) =>
        AssertRefused(TestHost.Allowlist(host.AllowlistEntry(clusterOverride: $"\"{name}\"")), "must be 1 to 253 letters");

    [Fact]
    public void RefusesHostWithoutKeys() =>
        AssertRefused("version: 1\nhosts:\n  - host: hv-host-01\n    keys: []\n", "has no keys");

    [Theory]
    [InlineData("", "empty")]
    [InlineData("version: 2\nhosts: []\n", "version")]
    [InlineData("version: 1\nhosts: []\n", "no hosts")]
    [InlineData("version: 1\nhosts: [", "not valid YAML")]
    public void RefusesBadDocument(string yaml, string messageFragment) =>
        AssertRefused(yaml, messageFragment);

    [Fact]
    public void RefusesOversizedFile() =>
        Assert.Throws<AllowlistException>(() => AllowlistParser.Parse(new byte[AllowlistParser.MaxFileBytes + 1]));

    [Fact]
    public void RandomBytesNeverThrowAnythingButAllowlistException()
    {
        // A cheap fuzz of our wrapper: whatever the file holds, the loader refuses it cleanly or accepts it.
        var random = new Random(8693);
        for (var i = 0; i < 500; i++)
        {
            var bytes = new byte[random.Next(0, 300)];
            random.NextBytes(bytes);
            try
            {
                AllowlistParser.Parse(bytes);
            }
            catch (AllowlistException)
            {
            }
        }

        var valid = TestHost.Allowlist(host.AllowlistEntry());
        for (var i = 0; i < 500; i++)
        {
            var chars = valid.ToCharArray();
            for (var j = 0; j < 3; j++)
            {
                chars[random.Next(chars.Length)] = (char)random.Next(32, 127);
            }

            try
            {
                Parse(new string(chars));
            }
            catch (AllowlistException)
            {
            }
        }
    }
}
