using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Proof.Issuer;

namespace Proof.Tests.Support;

/// <summary>
/// The issuer under test, with its allowlist and signing key in a temporary directory that tests can rewrite.
/// <see cref="IssuerOptions"/> stands in for the entry point because several referenced projects have a <c>Program</c>.
/// </summary>
public sealed class IssuerApp : WebApplicationFactory<IssuerOptions>
{
    private readonly string directory = Directory.CreateTempSubdirectory("proof-issuer-tests-").FullName;
    private readonly Dictionary<string, string?> settings;

    public IssuerApp(string allowlistYaml, Dictionary<string, string?>? overrides = null)
    {
        SigningKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(SigningKeyPath, SigningKey.ExportPkcs8PrivateKeyPem());
        WriteAllowlist(allowlistYaml);

        settings = new()
        {
            ["Proof:IssuerUrl"] = TestHost.IssuerUrl,
            ["Proof:AllowlistPath"] = AllowlistPath,
            ["Proof:SigningKeyPath"] = SigningKeyPath,
            ["Proof:AllowlistPollInterval"] = "01:00:00",
        };
        foreach (var (key, value) in overrides ?? [])
        {
            settings[key] = value;
        }
    }

    public ECDsa SigningKey { get; }
    public string AllowlistPath => Path.Combine(directory, "allowlist.yaml");
    public string SigningKeyPath => Path.Combine(directory, "signing-key.pem");

    public void WriteAllowlist(string yaml) => File.WriteAllText(AllowlistPath, yaml);

    public string WritePublicKey(string name, ECDsa key)
    {
        var path = Path.Combine(directory, name);
        File.WriteAllText(path, key.ExportSubjectPublicKeyInfoPem());
        return path;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        foreach (var (key, value) in settings)
        {
            builder.UseSetting(key, value);
        }
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing && Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
