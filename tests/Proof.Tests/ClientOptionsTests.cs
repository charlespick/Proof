using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Proof.Client;

namespace Proof.Tests;

/// <summary>The client's settings file and its TLS trust.</summary>
public sealed class ClientOptionsTests : IDisposable
{
    private readonly string directory = Directory.CreateTempSubdirectory("proof-client-options-tests-").FullName;

    public void Dispose() => Directory.Delete(directory, recursive: true);

    private ClientOptions Parse(string json) => ClientOptions.Parse(json, directory);

    [Fact]
    public void TokenEndpointDefaultsToTheIssuer()
    {
        var options = Parse("""{ "IssuerUrl": "https://id.example" }""");

        Assert.Equal("https://id.example", options.IssuerUrl);
        Assert.Equal(new Uri("https://id.example/token"), options.TokenEndpoint);
        Assert.Null(options.CaBundlePath);
    }

    [Fact]
    public void AcceptsAllSettingsWithCommentsAndAnyCase()
    {
        var options = Parse("""
            {
              // The public issuer; /token is internal.
              "issuerUrl": "https://id.example",
              "TOKENENDPOINT": "https://proof.internal.example/token",
              "CaBundlePath": "ca.pem",
            }
            """);

        Assert.Equal(new Uri("https://proof.internal.example/token"), options.TokenEndpoint);
        Assert.Equal(Path.Combine(directory, "ca.pem"), options.CaBundlePath);
    }

    [Theory]
    [InlineData("""{ }""", "IssuerUrl")]
    [InlineData("""{ "IssuerUrl": "http://id.example" }""", "IssuerUrl")]
    [InlineData("""{ "IssuerUrl": "https://id.example/" }""", "IssuerUrl")]
    [InlineData("""{ "IssuerUrl": 5 }""", "string")]
    [InlineData("""{ "IssuerUrl": "https://id.example", "TokenEndpoint": "http://id.example/token" }""", "TokenEndpoint")]
    [InlineData("""{ "IssuerUrl": "https://id.example", "TokenEndpoint": "https://id.example/token?x=1" }""", "TokenEndpoint")]
    [InlineData("""{ "IssuerUrl": "https://id.example", "IssuerURI": "https://id.example" }""", "Unknown setting")]
    [InlineData("""[ "https://id.example" ]""", "object")]
    [InlineData("""{ "IssuerUrl": """, "JSON")]
    public void RefusesBadSettings(string json, string message)
    {
        var ex = Assert.Throws<ClientConfigException>(() => Parse(json));

        Assert.Contains(message, ex.Message);
    }

    [Fact]
    public void AMissingFileSaysWhereItLooked()
    {
        var path = Path.Combine(directory, "config.json");

        var ex = Assert.Throws<ClientConfigException>(() => ClientOptions.Load(path));

        Assert.Contains(path, ex.Message);
    }

    [Fact]
    public void LoadsAFileAndItsCaBundle()
    {
        using var ca = CreateCa("Proof Test CA");
        File.WriteAllText(Path.Combine(directory, "ca.pem"), ca.ExportCertificatePem());
        File.WriteAllText(Path.Combine(directory, "config.json"), """{ "IssuerUrl": "https://id.example", "CaBundlePath": "ca.pem" }""");

        var options = ClientOptions.Load(Path.Combine(directory, "config.json"));
        var bundle = options.LoadCaBundle();

        Assert.Equal(ca.Thumbprint, Assert.Single(bundle!).Thumbprint);
    }

    [Fact]
    public void AnEmptyCaBundleIsRefused()
    {
        File.WriteAllText(Path.Combine(directory, "ca.pem"), "");
        var options = Parse("""{ "IssuerUrl": "https://id.example", "CaBundlePath": "ca.pem" }""");

        Assert.Throws<ClientConfigException>(() => options.LoadCaBundle());
    }

    // TLS against a CA bundle.

    [Fact]
    public void BundleTrustsACertificateFromItsCa()
    {
        using var ca = CreateCa("Proof Test CA");
        using var leaf = CreateLeaf(ca, serverAuth: true);

        Assert.True(TokenExchangeClient.ValidateWithBundle([ca], leaf, null, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void BundleRefusesACertificateFromAnotherCa()
    {
        using var ca = CreateCa("Proof Test CA");
        using var other = CreateCa("Other CA");
        using var leaf = CreateLeaf(other, serverAuth: true);

        Assert.False(TokenExchangeClient.ValidateWithBundle([ca], leaf, null, SslPolicyErrors.None));
    }

    [Fact]
    public void BundleRefusesANameMismatch()
    {
        using var ca = CreateCa("Proof Test CA");
        using var leaf = CreateLeaf(ca, serverAuth: true);

        Assert.False(TokenExchangeClient.ValidateWithBundle(
            [ca], leaf, null, SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch));
    }

    [Fact]
    public void BundleRefusesACertificateNotForServers()
    {
        using var ca = CreateCa("Proof Test CA");
        using var leaf = CreateLeaf(ca, serverAuth: false);

        Assert.False(TokenExchangeClient.ValidateWithBundle([ca], leaf, null, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    private static X509Certificate2 CreateCa(string name)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    private static X509Certificate2 CreateLeaf(X509Certificate2 ca, bool serverAuth)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=id.example", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid(serverAuth ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2")], false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("id.example");
        request.CertificateExtensions.Add(san.Build());
        return request.Create(ca, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(7), RandomNumberGenerator.GetBytes(8));
    }
}
