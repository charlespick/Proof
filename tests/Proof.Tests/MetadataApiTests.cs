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
    private const string NetworkData = """{"links": [{"id": "eth0", "type": "phy", "ethernet_mac_address": "00:15:5d:01:02:03", "mtu": 1500}], "networks": [{"id": "net0", "link": "eth0", "type": "ipv4", "ip_address": "192.0.2.10", "netmask": "255.255.255.0", "routes": [{"network": "0.0.0.0", "netmask": "0.0.0.0", "gateway": "192.0.2.1"}]}], "services": [{"type": "dns", "address": "192.0.2.53"}]}""";

    private const string Notes = $$"""
        #proof-metadata-begin
        meta-data:
          hostname: web01
          public_keys:
            my-key: ssh-ed25519 AAAA one
            other: ssh-ed25519 BBBB two
          availability_zone: rack-1
          meta:
            role: web
          admin_pass: !sensitive hunter2
        user-data: !sensitive |
          #cloud-config
          password: hunter3
        network-data: '{{NetworkData}}'
        #proof-metadata-end
        """;

    private const string Uuid = "00112233-4455-6677-8899-aabbccddeeff";
    private static readonly Guid BiosGuid = new(Uuid);

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

    private async Task<JsonElement> MetaData(string path = "/openstack/latest/meta_data.json")
    {
        var (status, body, response) = await Send(path);
        Assert.Equal(200, status);
        Assert.Equal("application/json", response.ContentType);
        return JsonDocument.Parse(body).RootElement;
    }

    [Theory]
    [InlineData("/openstack")]
    [InlineData("/openstack/")] // Cloud-init's combine_url, and Cloudbase-Init's posixpath.join, can add the slash.
    public async Task OnlyLatestIsListed(string path) => Assert.Equal("latest", await Ok(path));

    [Theory]
    // Cloudbase-Init posts the password it sets to the metadata service when this version exists.
    [InlineData("/openstack/2013-04-04/meta_data.json")]
    [InlineData("/openstack/2013-04-04/password")]
    [InlineData("/openstack/2012-08-10/meta_data.json")]
    [InlineData("/openstack/2018-08-27/network_data.json")]
    public async Task DatedVersionsAreNotServed(string path)
    {
        Assert.Equal(404, (await Send(path)).Status);
        Assert.Equal(0, channel.Requests); // So the answer doesn't depend on reaching the host.
    }

    [Fact]
    public async Task PasswordPostsAreRefused()
    {
        Assert.Equal(405, (await Send("/openstack/2013-04-04/password", "POST")).Status);
        Assert.Equal(405, (await Send("/openstack/latest/password", "POST")).Status);
        Assert.Equal(0, channel.Requests);
    }

    [Fact]
    public async Task RootListsOpenStack() => Assert.Equal("openstack", await Ok("/"));

    [Fact]
    public async Task LatestListsTheFilesThereAre()
    {
        Assert.Equal("meta_data.json\nnetwork_data.json\nuser_data", await Ok("/openstack/latest"));

        await vms.WriteNotesAsync(vm, "#proof-metadata-begin\nmeta-data:\n  hostname: a\n#proof-metadata-end", CancellationToken.None);
        time.Advance(TimeSpan.FromSeconds(6));
        Assert.Equal("meta_data.json", await Ok("/openstack/latest/"));
    }

    [Fact]
    public async Task MetaDataIsOpenStacksDocument()
    {
        var metaData = await MetaData();

        // Cloud-init requires uuid, and copies it to instance-id and hostname to local-hostname. Cloudbase-Init reads
        // uuid, hostname, admin_pass and the values of public_keys.
        Assert.Equal(Uuid, metaData.GetProperty("uuid").GetString());
        Assert.Equal("uuid", metaData.EnumerateObject().First().Name);
        Assert.Equal("web01", metaData.GetProperty("hostname").GetString());
        Assert.Equal("hunter2", metaData.GetProperty("admin_pass").GetString());
        Assert.Equal("rack-1", metaData.GetProperty("availability_zone").GetString());
        Assert.Equal("web", metaData.GetProperty("meta").GetProperty("role").GetString());
        var keys = metaData.GetProperty("public_keys");
        Assert.Equal("ssh-ed25519 AAAA one", keys.GetProperty("my-key").GetString());
        Assert.Equal("ssh-ed25519 BBBB two", keys.GetProperty("other").GetString());
    }

    [Fact]
    public async Task UuidIsTheBiosGuidAsTheGuestReadsItFromSmbios() =>
        // /sys/class/dmi/id/product_uuid on a Hyper-V guest, which cloud-init compares on every later boot.
        Assert.Equal("00112233-4455-6677-8899-aabbccddeeff", (await MetaData()).GetProperty("uuid").GetString());

    [Theory]
    [InlineData("\n    - ssh-rsa A\n    - ssh-rsa B", """{"key-0":"ssh-rsa A","key-1":"ssh-rsa B"}""")]
    [InlineData(" ssh-rsa A", """{"key-0":"ssh-rsa A"}""")]
    [InlineData("\n    one: ssh-rsa A", """{"one":"ssh-rsa A"}""")]
    public async Task PublicKeysAreAlwaysServedAsAMapping(string yaml, string expected)
    {
        // Cloudbase-Init reads only the values of a mapping.
        await vms.WriteNotesAsync(vm, $"#proof-metadata-begin\nmeta-data:\n  public_keys:{yaml}\n#proof-metadata-end", CancellationToken.None);
        Assert.Equal(expected, (await MetaData()).GetProperty("public_keys").GetRawText());
    }

    [Fact]
    public async Task NetworkDataIsServedAsWritten()
    {
        var (status, body, response) = await Send("/openstack/latest/network_data.json");
        Assert.Equal(200, status);
        Assert.Equal("application/json", response.ContentType);
        Assert.Equal(NetworkData, body);
    }

    [Fact]
    public async Task UserDataIsRawBytes()
    {
        var (status, body, response) = await Send("/openstack/latest/user_data");
        Assert.Equal(200, status);
        Assert.Equal("#cloud-config\npassword: hunter3\n", body);
        Assert.Equal("application/octet-stream", response.ContentType);
    }

    [Theory]
    [InlineData("/nope")]
    [InlineData("/latest/meta-data/instance-id")] // EC2's tree is gone.
    [InlineData("/latest/api/token")]
    [InlineData("/openstack/latest/nope")]
    [InlineData("/openstack/latest/vendor_data.json")]
    [InlineData("/openstack/latest/meta_data.json/more")]
    [InlineData("/openstack/latest/../latest/user_data")]
    [InlineData("/ec2/latest/meta-data.json")]
    public async Task UnknownPathsAre404(string path) => Assert.Equal(404, (await Send(path)).Status);

    [Fact]
    public async Task VmWithNoBlockGetsBasicDataAtOnceSoCloudInitDoesNotWait()
    {
        await vms.WriteNotesAsync(vm, "Just notes.", CancellationToken.None);

        Assert.Equal("latest", await Ok("/openstack"));
        Assert.Equal("meta_data.json", await Ok("/openstack/latest"));
        Assert.Equal($$"""{"uuid":"{{Uuid}}","hostname":"from-vm-name"}""", (await MetaData()).GetRawText());
        Assert.Equal(404, (await Send("/openstack/latest/user_data")).Status);
        Assert.Equal(404, (await Send("/openstack/latest/network_data.json")).Status);
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
        Assert.Contains($"instance-id: {Uuid} }}", vms.Notes(vm));
    }

    [Fact]
    public async Task WithHandler404AVmWithNoBlockGets404()
    {
        await vms.WriteNotesAsync(vm, "Just notes.", CancellationToken.None);
        var strict = new MetadataApi(new Channel(NewHandler("404"), vm), time, NullLogger<MetadataApi>.Instance);

        foreach (var (path, method) in new[] { ("/openstack", "GET"), ("/openstack/latest/meta_data.json", "GET"), (MetadataApi.ProvisioningPath, "GET"), (MetadataApi.ProvisioningPath + "/complete", "POST") })
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

    [Theory]
    [InlineData("/openstack")] // What cloud-init polls until max_wait, so it waits for the host too.
    [InlineData("/openstack/latest/meta_data.json")]
    public async Task HostUnreachableIs503SoClientsRetry(string path)
    {
        channel.Down = true;
        Assert.Equal(503, (await Send(path)).Status);
        Assert.Equal(503, (await Send(MetadataApi.ProvisioningPath + "/complete", "POST")).Status);

        // And the failure was not kept.
        channel.Down = false;
        Assert.Equal(200, (await Send(path)).Status);
    }

    [Fact]
    public async Task InvalidBlockIs503()
    {
        await vms.WriteNotesAsync(vm, "#proof-metadata-begin\nbogus: 1\n#proof-metadata-end", CancellationToken.None);
        Assert.Equal(503, (await Send("/openstack")).Status);
        Assert.Equal(503, (await Send("/openstack/latest/meta_data.json")).Status);
    }

    [Fact]
    public async Task CompletionClearsSecretsAtOnceDespiteTheCache()
    {
        Assert.Equal("hunter2", (await MetaData()).GetProperty("admin_pass").GetString());
        Assert.Equal("pending", await Ok(MetadataApi.ProvisioningPath));

        // cloud-init's phone_home posts a form here.
        var (status, body, _) = await Send(MetadataApi.ProvisioningPath + "/complete", "POST");

        Assert.Equal(200, status);
        Assert.Equal("complete", body);
        Assert.False((await MetaData()).TryGetProperty("admin_pass", out _));
        Assert.Equal(404, (await Send("/openstack/latest/user_data")).Status);
        Assert.Equal(200, (await Send("/openstack/latest/network_data.json")).Status); // Not sensitive, so it stays.
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
    public async Task MetadataIsReadOnly(string method) => Assert.Equal(405, (await Send("/openstack/latest/meta_data.json", method)).Status);

    [Fact]
    public async Task CacheCoalescesACrawlAndExpires()
    {
        await Ok("/openstack");
        await Ok("/openstack/latest/meta_data.json");
        await Ok("/openstack/latest/user_data");
        await Ok("/openstack/latest/network_data.json");
        Assert.Equal(1, channel.Requests);

        time.Advance(TimeSpan.FromSeconds(6));
        await Ok("/openstack/latest/meta_data.json");
        Assert.Equal(2, channel.Requests);
    }

    [Theory]
    [InlineData("169.254.169.254")]
    [InlineData("evil.example:8169")] // A page that rebinds its name to loopback.
    [InlineData("127.0.0.1.evil.example")]
    public async Task OtherHostNamesAreRefused(string host)
    {
        Assert.Equal(403, (await Send("/openstack/latest/user_data", host: host)).Status);
        Assert.Equal(0, channel.Requests);
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("localhost:8169")]
    [InlineData("127.0.0.1")]
    [InlineData("[::1]:8169")]
    public async Task LoopbackHostNamesAreAccepted(string host) =>
        Assert.Equal(200, (await Send("/openstack/latest/meta_data.json", host: host)).Status);

    [Fact]
    public async Task WebPagesCannotReportCompletion()
    {
        // A form post from any page in a browser in this VM reaches loopback with the right Host, and carries Origin.
        var (status, _, _) = await Send(MetadataApi.ProvisioningPath + "/complete", "POST", headers: ("Origin", "https://evil.example"));
        Assert.Equal(403, status);
        Assert.Contains("!sensitive", vms.Notes(vm));
    }

    [Fact]
    public async Task WebPagesCannotReadMetadata() =>
        Assert.Equal(403, (await Send("/openstack/latest/user_data", headers: ("Origin", "https://evil.example"))).Status);

    [Fact]
    public async Task ForwardedRequestsAreRefused() =>
        Assert.Equal(403, (await Send("/openstack/latest/user_data", headers: ("X-Forwarded-For", "10.0.0.1"))).Status);

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
