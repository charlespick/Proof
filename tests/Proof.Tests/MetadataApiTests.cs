using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Proof.Metadata;
using Proof.Refresher.Metadata;
using Proof.Shared;
using Proof.Tests.Support;

namespace Proof.Tests;

/// <summary>The local API, in the shapes cloud-init and Cloudbase-Init read, over the real host-side handler.</summary>
public class MetadataApiTests
{
    private const string Notes = """
        #proof-metadata-begin
        meta-data:
          local-hostname: web01
          public-keys:
            my-key: ssh-ed25519 AAAA one
            other: ssh-ed25519 BBBB two
          placement:
            availability-zone: rack-1
          security-groups:
            - a
            - b
          disks:
            - name: sda
            - name: sdb
          admin-pass: !sensitive hunter2
        user-data: !sensitive |
          #cloud-config
          password: hunter3
        #proof-metadata-end
        """;

    private static readonly Guid BiosGuid = new("00112233-4455-6677-8899-aabbccddeeff");

    private readonly FakeVmNotes vms = new();
    private readonly ManualTime time = new(new DateTimeOffset(2026, 10, 31, 12, 0, 0, TimeSpan.Zero));
    private readonly Channel channel;
    private readonly MetadataApi api;
    private readonly Guid vm;

    public MetadataApiTests()
    {
        vm = vms.Add("from-vm-name", BiosGuid, Notes.ReplaceLineEndings("\n"));
        channel = new Channel(NewHandler("minimal"), vm);
        api = new MetadataApi(channel, time, NullLogger<MetadataApi>.Instance);
    }

    private MetadataRequestHandler NewHandler(string handler) => new(
        vms,
        Microsoft.Extensions.Options.Options.Create(new Proof.Refresher.RefresherOptions { IssuerUrl = TestHost.IssuerUrl, UnsetMetadataHandler = handler }),
        time,
        NullLogger<MetadataRequestHandler>.Instance);

    private async Task<(int Status, string Body, HttpResponse Response)> Send(
        string path, string method = "GET", string host = "127.0.0.1:8169", params (string Name, string Value)[] headers)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Request.Host = new HostString(host);
        foreach (var (name, value) in headers)
        {
            context.Request.Headers[name] = value;
        }

        var body = new MemoryStream();
        context.Response.Body = body;
        await api.HandleAsync(context);
        return (context.Response.StatusCode, Encoding.UTF8.GetString(body.ToArray()), context.Response);
    }

    private async Task<string> Ok(string path)
    {
        var (status, body, _) = await Send(path);
        Assert.Equal(200, status);
        return body;
    }

    [Fact]
    public async Task RootListsVersionsIncludingThoseTheClientsAskFor()
    {
        var versions = (await Ok("/")).Split('\n');
        Assert.Contains("latest", versions);
        Assert.Contains("2009-04-04", versions); // Cloud-init's minimum, and Cloudbase-Init's only version.
    }

    [Theory]
    [InlineData("/latest/meta-data/instance-id")]
    [InlineData("/2009-04-04/meta-data/instance-id")] // Cloudbase-Init.
    [InlineData("/2021-03-23/meta-data/instance-id")] // Cloud-init's newest.
    [InlineData("/2018-09-24/meta-data/instance-id")]
    public async Task InstanceIdIsFromTheBiosGuidAtEveryVersion(string path) =>
        Assert.Equal("i-00112233445566778899aabbccddeeff", await Ok(path));

    [Theory]
    [InlineData("/latest/meta-data")]
    [InlineData("/latest/meta-data/")] // Cloud-init crawls with the slash.
    public async Task MetaDataListsChildrenWithSlashesOnDirectories(string path)
    {
        var list = (await Ok(path)).Split('\n');
        Assert.Contains("instance-id", list);
        Assert.Contains("local-hostname", list);
        Assert.Contains("public-keys/", list);
        Assert.Contains("placement/", list);
        Assert.Contains("security-groups", list);
        Assert.Contains("admin-pass", list);
    }

    [Fact]
    public async Task VersionListsItsChildren() => Assert.Equal("meta-data\nuser-data", await Ok("/latest"));

    [Fact]
    public async Task PublicKeysAreWalkedAsTheClientsDo()
    {
        // Both clients read this list, split each line on '=', and then fetch <index>/openssh-key.
        Assert.Equal("0=my-key\n1=other", await Ok("/2009-04-04/meta-data/public-keys"));
        Assert.Equal("0=my-key\n1=other", await Ok("/latest/meta-data/public-keys/"));
        Assert.Equal("openssh-key", await Ok("/latest/meta-data/public-keys/0/"));
        Assert.Equal("ssh-ed25519 AAAA one", await Ok("/2009-04-04/meta-data/public-keys/0/openssh-key"));
        Assert.Equal("ssh-ed25519 BBBB two", await Ok("/latest/meta-data/public-keys/1/openssh-key"));
    }

    [Theory]
    [InlineData("\n    - ssh-rsa A\n    - ssh-rsa B", "0=key-0\n1=key-1")]
    [InlineData(" ssh-rsa A", "0=key-0")]
    public async Task PublicKeysMayBeAListOrOneKey(string yaml, string expected)
    {
        await vms.WriteNotesAsync(vm, $"#proof-metadata-begin\nmeta-data:\n  public-keys:{yaml}\n#proof-metadata-end", CancellationToken.None);
        Assert.Equal(expected, await Ok("/latest/meta-data/public-keys"));
    }

    [Fact]
    public async Task NestedValuesAndListsAreServed()
    {
        Assert.Equal("availability-zone", await Ok("/latest/meta-data/placement/"));
        Assert.Equal("rack-1", await Ok("/latest/meta-data/placement/availability-zone"));
        Assert.Equal("a\nb", await Ok("/latest/meta-data/security-groups"));
        Assert.Equal("0/\n1/", await Ok("/latest/meta-data/disks"));
        Assert.Equal("sdb", await Ok("/latest/meta-data/disks/1/name"));
    }

    [Fact]
    public async Task UserDataIsRawBytes()
    {
        var (status, body, response) = await Send("/latest/user-data");
        Assert.Equal(200, status);
        Assert.Equal("#cloud-config\npassword: hunter3\n", body);
        Assert.Equal("application/octet-stream", response.ContentType);
        Assert.Equal("#cloud-config\npassword: hunter3\n", await Ok("/2009-04-04/user-data")); // Cloudbase-Init.
    }

    [Theory]
    [InlineData("/nope")]
    [InlineData("/latest/nope")]
    [InlineData("/latest/meta-data/nope")]
    [InlineData("/latest/meta-data/instance-id/more")]
    [InlineData("/latest/meta-data/public-keys/9/openssh-key")]
    [InlineData("/not-a-version/meta-data/instance-id")]
    [InlineData("/latest/meta-data/../../user-data")]
    public async Task UnknownPathsAre404(string path) => Assert.Equal(404, (await Send(path)).Status);

    [Fact]
    public async Task VmWithNoBlockGetsBasicDataAtOnceSoCloudInitDoesNotWait()
    {
        await vms.WriteNotesAsync(vm, "Just notes.", CancellationToken.None);

        Assert.Equal("i-00112233445566778899aabbccddeeff", await Ok("/2009-04-04/meta-data/instance-id"));
        Assert.Equal("instance-id\nlocal-hostname", await Ok("/latest/meta-data/"));
        Assert.Equal("from-vm-name", await Ok("/latest/meta-data/local-hostname"));
        Assert.Equal("meta-data", await Ok("/latest"));
        Assert.Equal(404, (await Send("/latest/user-data")).Status);
        Assert.Equal("none", await Ok(MetadataApi.ProvisioningPath));
    }

    [Fact]
    public async Task PhoneHomeWithNoBlockIsRecordedInTheNotes()
    {
        await vms.WriteNotesAsync(vm, "Just notes.", CancellationToken.None);

        var (status, body, _) = await Send(MetadataApi.ProvisioningPath + "/complete", "POST");

        Assert.Equal(200, status);
        Assert.Equal("complete", body);
        Assert.Equal("complete", await Ok(MetadataApi.ProvisioningPath));
        Assert.StartsWith("Just notes.\r\n#proof-metadata-begin\r\nprovisioning: { status: complete", vms.Notes(vm));
    }

    [Fact]
    public async Task WithHandler404AVmWithNoBlockGets404()
    {
        await vms.WriteNotesAsync(vm, "Just notes.", CancellationToken.None);
        var strict = new MetadataApi(new Channel(NewHandler("404"), vm), time, NullLogger<MetadataApi>.Instance);

        foreach (var (path, method) in new[] { ("/latest/meta-data/instance-id", "GET"), (MetadataApi.ProvisioningPath, "GET"), (MetadataApi.ProvisioningPath + "/complete", "POST") })
        {
            var context = new DefaultHttpContext();
            context.Request.Method = method;
            context.Request.Path = path;
            context.Request.Host = new HostString("127.0.0.1:8169");
            context.Response.Body = new MemoryStream();
            await strict.HandleAsync(context);
            Assert.Equal(404, context.Response.StatusCode);
        }

        Assert.Equal("Just notes.", vms.Notes(vm));
    }

    [Fact]
    public async Task HostUnreachableIs503ForEveryPathSoClientsRetry()
    {
        channel.Down = true;
        Assert.Equal(503, (await Send("/latest/meta-data/instance-id")).Status);
        Assert.Equal(503, (await Send(MetadataApi.ProvisioningPath + "/complete", "POST")).Status);

        // And the failure was not kept.
        channel.Down = false;
        Assert.Equal(200, (await Send("/latest/meta-data/instance-id")).Status);
    }

    [Fact]
    public async Task InvalidBlockIs503()
    {
        await vms.WriteNotesAsync(vm, "#proof-metadata-begin\nbogus: 1\n#proof-metadata-end", CancellationToken.None);
        Assert.Equal(503, (await Send("/latest/meta-data/instance-id")).Status);
    }

    [Fact]
    public async Task CompletionClearsSecretsAtOnceDespiteTheCache()
    {
        Assert.Equal("hunter2", await Ok("/latest/meta-data/admin-pass"));
        Assert.Equal("pending", await Ok(MetadataApi.ProvisioningPath));

        // cloud-init's phone_home posts a form here.
        var (status, body, _) = await Send(MetadataApi.ProvisioningPath + "/complete", "POST");

        Assert.Equal(200, status);
        Assert.Equal("complete", body);
        Assert.Equal(404, (await Send("/latest/meta-data/admin-pass")).Status);
        Assert.Equal(404, (await Send("/latest/user-data")).Status);
        Assert.Equal("complete", await Ok(MetadataApi.ProvisioningPath));
        Assert.DoesNotContain("hunter", vms.Notes(vm));
    }

    [Fact]
    public async Task FailureIsRecordedAndClearsToo()
    {
        Assert.Equal("failed", (await Send(MetadataApi.ProvisioningPath + "/failed", "POST")).Body);
        Assert.DoesNotContain("hunter", vms.Notes(vm));
    }

    [Theory]
    [InlineData("GET", "/complete")]
    [InlineData("POST", "")]
    [InlineData("POST", "/pending")]
    [InlineData("POST", "/complete/more")]
    public async Task OnlyAPostOfAResultFinishes(string method, string suffix)
    {
        Assert.Equal(404, (await Send(MetadataApi.ProvisioningPath + suffix, method)).Status);
        Assert.Contains("!sensitive", vms.Notes(vm));
    }

    [Theory]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    public async Task TreeIsReadOnly(string method) => Assert.Equal(405, (await Send("/latest/meta-data/instance-id", method)).Status);

    [Fact]
    public async Task CacheCoalescesACrawlAndExpires()
    {
        await Ok("/latest/meta-data/");
        await Ok("/latest/meta-data/instance-id");
        await Ok("/latest/user-data");
        Assert.Equal(1, channel.Requests);

        time.Advance(TimeSpan.FromSeconds(6));
        await Ok("/latest/meta-data/instance-id");
        Assert.Equal(2, channel.Requests);
    }

    [Theory]
    [InlineData("169.254.169.254")]
    [InlineData("evil.example:8169")] // A page that rebinds its name to loopback.
    [InlineData("127.0.0.1.evil.example")]
    public async Task OtherHostNamesAreRefused(string host)
    {
        Assert.Equal(403, (await Send("/latest/user-data", host: host)).Status);
        Assert.Equal(0, channel.Requests);
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("localhost:8169")]
    [InlineData("127.0.0.1")]
    [InlineData("[::1]:8169")]
    public async Task LoopbackHostNamesAreAccepted(string host) =>
        Assert.Equal(200, (await Send("/latest/meta-data/instance-id", host: host)).Status);

    [Fact]
    public async Task WebPagesCannotReportCompletion()
    {
        // A form post from any page in a browser in this VM reaches loopback with the right Host, and carries Origin.
        var (status, _, _) = await Send(MetadataApi.ProvisioningPath + "/complete", "POST", headers: ("Origin", "https://evil.example"));
        Assert.Equal(403, status);
        Assert.Contains("!sensitive", vms.Notes(vm));
    }

    [Fact]
    public async Task ForwardedRequestsAreRefused() =>
        Assert.Equal(403, (await Send("/latest/user-data", headers: ("X-Forwarded-For", "10.0.0.1"))).Status);

    [Fact]
    public async Task TokenIsIssuedAndAcceptedThenExpires()
    {
        var (status, token, response) = await Send(MetadataApi.TokenPath, "PUT", headers: ("X-aws-ec2-metadata-token-ttl-seconds", "60"));
        Assert.Equal(200, status);
        Assert.Equal("60", response.Headers["X-aws-ec2-metadata-token-ttl-seconds"]);

        Assert.Equal(200, (await Send("/latest/meta-data/instance-id", headers: ("X-aws-ec2-metadata-token", token))).Status);

        time.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal(401, (await Send("/latest/meta-data/instance-id", headers: ("X-aws-ec2-metadata-token", token))).Status);
    }

    [Theory]
    [InlineData("rubbish")]
    [InlineData("9999999999.AAAA")]
    public async Task WrongTokensAre401(string token) =>
        Assert.Equal(401, (await Send("/latest/meta-data/instance-id", headers: ("X-aws-ec2-metadata-token", token))).Status);

    [Fact]
    public async Task NoTokenIsAllowedForImdsV1Clients() => Assert.Equal(200, (await Send("/latest/meta-data/instance-id")).Status);

    [Theory]
    [InlineData(null)]
    [InlineData("0")]
    [InlineData("21601")]
    [InlineData("abc")]
    public async Task TokenNeedsAValidTtl(string? ttl)
    {
        (string, string)[] headers = ttl is null ? [] : [("X-aws-ec2-metadata-token-ttl-seconds", ttl)];
        Assert.Equal(400, (await Send(MetadataApi.TokenPath, "PUT", headers: headers)).Status);
    }

    [Fact]
    public async Task TokenRouteIsPutOnly() => Assert.Equal(405, (await Send(MetadataApi.TokenPath)).Status);

    /// <summary>The socket, as far as the two ends see it: JSON both ways, and the VM ID from outside the request.</summary>
    private sealed class Channel(MetadataRequestHandler handler, Guid vm) : IHostChannel
    {
        public bool Down { get; set; }

        public int Requests { get; private set; }

        public async Task<MetadataResponse> SendAsync(MetadataRequest request, CancellationToken cancellationToken)
        {
            Requests++;
            if (Down)
            {
                throw new IOException("Host down.");
            }

            var response = await handler.HandleAsync(vm, request, cancellationToken);
            return JsonSerializer.Deserialize(JsonSerializer.Serialize(response, MetadataJsonContext.Default.MetadataResponse), MetadataJsonContext.Default.MetadataResponse)!;
        }
    }
}
