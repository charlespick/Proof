using System.Runtime.Versioning;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Proof.Client;
using Proof.Shared;
using Proof.Tests.Support;

namespace Proof.Tests;

/// <summary>The client's commands end to end: a host token in a fake KVP pool, exchanged at the real issuer.</summary>
public sealed class ClientTests : IDisposable
{
    private readonly TestHost host = new();
    private readonly IssuerApp app;
    private readonly HttpClient http;
    private readonly FakeKvp kvp = new();
    private readonly StringWriter stdout = new();
    private readonly StringWriter stderr = new();
    private readonly string directory = Directory.CreateTempSubdirectory("proof-client-tests-").FullName;
    private readonly ClientOptions options;

    public ClientTests()
    {
        app = new IssuerApp(TestHost.Allowlist(host.AllowlistEntry()));
        http = app.CreateClient();
        // The test server speaks plain HTTP, which only a configuration file is checked for.
        options = new ClientOptions { IssuerUrl = TestHost.IssuerUrl, TokenEndpoint = new Uri(http.BaseAddress!, TokenExchange.EndpointPath) };
        kvp.Parameters[GuestParameterNames.PhysicalHostName] = "HV-HOST-01";
    }

    public void Dispose()
    {
        http.Dispose();
        app.Dispose();
        Directory.Delete(directory, recursive: true);
    }

    private ClientCommands Commands => new(kvp, TimeProvider.System, stdout, stderr);

    private Task<int> TokenAsync(string audience = "my-service", string? outPath = null, TimeSpan wait = default) =>
        Commands.TokenAsync(options, http, audience, outPath, wait, TestContext.Current.CancellationToken);

    private string ExpiredHostToken() => host.CreateToken(c =>
    {
        var past = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds();
        c[JwtRegisteredClaimNames.Iat] = past;
        c[JwtRegisteredClaimNames.Nbf] = past;
        c[JwtRegisteredClaimNames.Exp] = past + (long)HostTokenPolicy.Lifetime.TotalSeconds;
    });

    private async Task<TokenValidationResult> ValidateIssuedAsync(string token, string audience) =>
        await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = TestHost.IssuerUrl,
            ValidAudience = audience,
            IssuerSigningKey = new ECDsaSecurityKey(app.SigningKey),
            ValidAlgorithms = [ProofAlgorithms.Signing],
        });

    // token

    [Fact]
    public async Task PrintsAJwtForTheAudience()
    {
        kvp.Token = host.CreateToken();

        Assert.Equal(ExitCodes.Ok, await TokenAsync("my-service"));

        var printed = stdout.ToString();
        Assert.EndsWith(Environment.NewLine, printed);
        var result = await ValidateIssuedAsync(printed.TrimEnd(), "my-service");
        Assert.True(result.IsValid, result.Exception?.Message);
        Assert.Equal(TestHost.VmId, ((JsonWebToken)result.SecurityToken).Subject);
        Assert.Empty(stderr.ToString());
    }

    [Fact]
    public async Task WritesATokenFile()
    {
        kvp.Token = host.CreateToken();
        var path = Path.Combine(directory, "token");
        File.WriteAllText(path, "old");

        Assert.Equal(ExitCodes.Ok, await TokenAsync("sts.example", path));

        var written = File.ReadAllText(path);
        Assert.DoesNotContain("\n", written);
        Assert.True((await ValidateIssuedAsync(written, "sts.example")).IsValid);
        Assert.Empty(stdout.ToString());
        Assert.Contains("sts.example", stderr.ToString());
        Assert.Equal(["token"], Directory.GetFiles(directory).Select(Path.GetFileName));
    }

    [Fact]
    [UnsupportedOSPlatform("windows")]
    public void ANewTokenFileIsPrivateAndAReplacedOneKeepsItsMode()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Unix file modes.");
        var path = Path.Combine(directory, "token");

        TokenFile.Write(path, "first");
        Assert.Equal(TokenFile.NewFileMode, File.GetUnixFileMode(path));

        var shared = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead;
        File.SetUnixFileMode(path, shared);
        TokenFile.Write(path, "second");

        Assert.Equal("second", File.ReadAllText(path));
        Assert.Equal(shared, File.GetUnixFileMode(path));
    }

    [Fact]
    public async Task NoHostTokenExitsWithRetryCode()
    {
        Assert.Equal(ExitCodes.NoHostToken, await TokenAsync());

        Assert.Contains(KvpKeys.Token, stderr.ToString());
        Assert.Contains("HV-HOST-01", stderr.ToString());
        Assert.Empty(stdout.ToString());
    }

    [Fact]
    public async Task WaitsForTheHostToWriteAToken()
    {
        kvp.BeforeRead = k =>
        {
            if (k.Reads == 2)
            {
                k.Token = host.CreateToken();
            }
        };

        Assert.Equal(ExitCodes.Ok, await TokenAsync(wait: TimeSpan.FromSeconds(10)));

        Assert.Equal(2, kvp.Reads);
    }

    [Fact]
    public async Task WaitsPastAnUnavailablePoolAndAnExpiredToken()
    {
        kvp.Unavailable = new KvpUnavailableException("not yet");
        kvp.BeforeRead = k =>
        {
            if (k.Reads == 2)
            {
                k.Unavailable = null;
                k.Token = ExpiredHostToken();
            }
            else if (k.Reads == 3)
            {
                k.Token = host.CreateToken();
            }
        };

        Assert.Equal(ExitCodes.Ok, await TokenAsync(wait: TimeSpan.FromSeconds(10)));

        Assert.Equal(3, kvp.Reads);
    }

    [Fact]
    public async Task GivesUpWaitingAndSendsWhatItHas()
    {
        kvp.Token = ExpiredHostToken();

        Assert.Equal(ExitCodes.Failed, await TokenAsync(wait: TimeSpan.FromSeconds(1)));

        Assert.Contains("expired", stderr.ToString());
    }

    [Fact]
    public async Task ExplainsAnExpiredHostToken()
    {
        kvp.Token = ExpiredHostToken();

        Assert.Equal(ExitCodes.Failed, await TokenAsync());

        var error = stderr.ToString();
        Assert.Contains("invalid_request", error);
        Assert.Contains("expired", error);
        Assert.Contains(host.HostId, error);
        Assert.Empty(stdout.ToString());
    }

    [Fact]
    public async Task ExplainsAnIssuerMismatch()
    {
        kvp.Token = host.CreateToken(c => c[JwtRegisteredClaimNames.Aud] = "https://other.example");

        Assert.Equal(ExitCodes.Failed, await TokenAsync());

        Assert.Contains("https://other.example", stderr.ToString());
    }

    [Fact]
    public async Task SaysWhenTheTokenLooksRightButIsRefused()
    {
        kvp.Token = new TestHost("hv-unknown").CreateToken();

        Assert.Equal(ExitCodes.Failed, await TokenAsync());

        Assert.Contains("allowlist", stderr.ToString());
        Assert.Contains("hv-unknown", stderr.ToString());
    }

    [Fact]
    public async Task ReportsAnUnreachableIssuer()
    {
        kvp.Token = host.CreateToken();
        using var unreachable = new HttpClient(new FailingHandler());

        var code = await Commands.TokenAsync(options, unreachable, "my-service", null, TimeSpan.Zero, TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Failed, code);
        Assert.Contains("cannot reach the issuer", stderr.ToString());
    }

    [Fact]
    public async Task TheHostTokenNeverReachesOutput()
    {
        var hostToken = host.CreateToken();
        kvp.Token = hostToken;
        await TokenAsync();
        Commands.Status(options, null);

        Assert.DoesNotContain(hostToken, stdout.ToString());
        Assert.DoesNotContain(hostToken, stderr.ToString());
    }

    // status

    [Fact]
    public void StatusDescribesTheHostToken()
    {
        kvp.Token = host.CreateToken();
        kvp.Parameters[GuestParameterNames.VirtualMachineId] = TestHost.VmId.ToUpperInvariant();

        Assert.Equal(ExitCodes.Ok, Commands.Status(options, null));

        var output = stdout.ToString();
        Assert.Contains(TestHost.VmId, output);
        Assert.Contains("web01", output);
        Assert.Contains(host.Kid, output);
        Assert.Contains("HV-HOST-01", output);
        Assert.Contains("No problems found.", output);
        Assert.DoesNotContain("Warnings", output);
    }

    [Fact]
    public void StatusWithoutAHostToken()
    {
        Assert.Equal(ExitCodes.NoHostToken, Commands.Status(options, null));

        Assert.Contains("No host token", stdout.ToString());
    }

    [Fact]
    public void StatusReportsProblems()
    {
        kvp.Token = ExpiredHostToken();
        kvp.AgentProblem = "hv_kvp_daemon is not running.";

        Assert.Equal(ExitCodes.Failed, Commands.Status(null, "No configuration at /etc/proof/config.json."));

        var output = stdout.ToString();
        Assert.Contains("expired", output);
        Assert.Contains("hv_kvp_daemon", output);
        Assert.Contains("No configuration", output);
    }

    [Fact]
    public void StatusWarnsWhenTheTokenNamesAnotherVm()
    {
        kvp.Token = host.CreateToken();
        kvp.Parameters[GuestParameterNames.VirtualMachineId] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

        Assert.Equal(ExitCodes.Ok, Commands.Status(options, null));

        Assert.Contains("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", stdout.ToString());
        Assert.Contains("Warnings", stdout.ToString());
    }

    [Fact]
    public void StatusWarnsAboutATokenThatWasNotRenewed()
    {
        kvp.Token = host.CreateToken(c =>
        {
            var t = DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeSeconds();
            c[JwtRegisteredClaimNames.Iat] = t;
            c[JwtRegisteredClaimNames.Nbf] = t;
            c[JwtRegisteredClaimNames.Exp] = t + (long)HostTokenPolicy.Lifetime.TotalSeconds;
        });

        Assert.Equal(ExitCodes.Ok, Commands.Status(options, null));

        Assert.Contains("should have been renewed", stdout.ToString());
    }

    [Fact]
    public void StatusReportsAMalformedToken()
    {
        kvp.Token = "not-a-jwt";

        Assert.Equal(ExitCodes.Failed, Commands.Status(options, null));

        Assert.Contains("malformed", stdout.ToString());
    }

    private sealed class FailingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("Connection refused");
    }
}
