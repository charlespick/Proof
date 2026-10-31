using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Proof.Refresher;
using Proof.Refresher.Metadata;
using Proof.Shared;
using Proof.Tests.Support;

namespace Proof.Tests;

public class MetadataHostTests
{
    private const string InstanceId = "i-00112233445566778899aabbccddeeff";
    private static readonly Guid BiosGuid = new("00112233-4455-6677-8899-aabbccddeeff");

    private readonly FakeVmNotes vms = new();
    private readonly MetadataRequestHandler handler;

    public MetadataHostTests()
    {
        handler = NewHandler("minimal");
    }

    private MetadataRequestHandler NewHandler(string handler) => new(
        vms,
        Options.Create(new RefresherOptions { IssuerUrl = TestHost.IssuerUrl, UnsetMetadataHandler = handler }),
        TimeProvider.System,
        NullLogger<MetadataRequestHandler>.Instance);

    private static string Enrolled(string yaml) => $"{VmMetadataBlock.BeginMarker}\n{yaml}{VmMetadataBlock.EndMarker}\n";

    private Task<MetadataResponse> Get(Guid id) => handler.HandleAsync(id, new MetadataRequest(MetadataOperations.Get), CancellationToken.None);

    private Task<MetadataResponse> Finish(Guid id, string result) => handler.HandleAsync(id, new MetadataRequest(MetadataOperations.Finish, result), CancellationToken.None);

    [Fact]
    public async Task UnknownCallerIsNotEnrolled() => Assert.Equal(MetadataResponseStatus.NotEnrolled, (await Get(Guid.NewGuid())).Status);

    [Fact]
    public async Task UnknownCallerFinishingChangesNothing()
    {
        Assert.Equal(MetadataResponseStatus.NotEnrolled, (await Finish(Guid.NewGuid(), ProvisioningStatus.Complete)).Status);
        Assert.Equal(0, vms.Writes);
    }

    [Fact]
    public async Task VmWithoutTheBlockGetsBasicDataOnlyAndReadingWritesNothing()
    {
        var vm = vms.Add("web01", BiosGuid, "password: hunter2");

        var response = await Get(vm);

        Assert.Equal(MetadataResponseStatus.Ok, response.Status);
        Assert.Equal(InstanceId, response.InstanceId);
        Assert.Equal(ProvisioningStatus.None, response.Provisioning);
        Assert.Null(response.UserData);
        Assert.Equal("local-hostname", Assert.Single(response.MetaData!.Value.EnumerateObject()).Name);
        Assert.Equal("password: hunter2", vms.Notes(vm));
        Assert.Equal(0, vms.Writes);
    }

    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("Some notes.", "Some notes.\r\n")]
    [InlineData("Line one\r\nLine two\r\n", "Line one\r\nLine two\r\n")]
    public async Task PhoneHomeWithoutTheBlockAppendsTheLeastThatRecordsIt(string? notes, string kept)
    {
        var vm = vms.Add("web01", BiosGuid, notes);

        var response = await Finish(vm, ProvisioningStatus.Complete);

        Assert.Equal(MetadataResponseStatus.Ok, response.Status);
        Assert.Equal(ProvisioningStatus.Complete, response.Provisioning);
        var written = vms.Notes(vm)!;
        Assert.StartsWith(kept + "#proof-metadata-begin\r\nprovisioning: { status: complete, at: \"", written);
        Assert.EndsWith($"\", instance-id: {InstanceId} }}\r\n#proof-metadata-end\r\n", written);
        Assert.Equal(ProvisioningStatus.Complete, (await Get(vm)).Provisioning);
        Assert.Equal(InstanceId, (await Get(vm)).InstanceId);

        // A retry, or a later report, changes nothing.
        Assert.Equal(ProvisioningStatus.Complete, (await Finish(vm, ProvisioningStatus.Failed)).Provisioning);
        Assert.Equal(1, vms.Writes);
    }

    [Fact]
    public async Task AppendedBlockFollowsTheNotesLineEnds()
    {
        var vm = vms.Add("web01", BiosGuid, "One\nTwo");
        await Finish(vm, ProvisioningStatus.Failed);
        Assert.DoesNotContain('\r', vms.Notes(vm)!);
        Assert.StartsWith("One\nTwo\n#proof-metadata-begin\nprovisioning: { status: failed,", vms.Notes(vm));
    }

    [Fact]
    public async Task WithHandler404AVmWithoutTheBlockGetsNothingAndNothingIsRecorded()
    {
        var strict = NewHandler("404");
        var vm = vms.Add("web01", BiosGuid, "Some notes.");

        var read = await strict.HandleAsync(vm, new MetadataRequest(MetadataOperations.Get), CancellationToken.None);
        var finish = await strict.HandleAsync(vm, new MetadataRequest(MetadataOperations.Finish, ProvisioningStatus.Complete), CancellationToken.None);

        Assert.Equal(MetadataResponseStatus.NotEnrolled, read.Status);
        Assert.Null(read.InstanceId);
        Assert.Equal(MetadataResponseStatus.NotEnrolled, finish.Status);
        Assert.Equal("Some notes.", vms.Notes(vm));
        Assert.Equal(0, vms.Writes);
    }

    [Fact]
    public async Task WithHandler404AVmWithTheBlockIsServedAsUsual()
    {
        var vm = vms.Add("web01", BiosGuid, Enrolled("user-data: mine\n"));
        var read = await NewHandler("404").HandleAsync(vm, new MetadataRequest(MetadataOperations.Get), CancellationToken.None);
        Assert.Equal("mine", read.UserData);
    }

    [Theory]
    [InlineData("minimal", true)]
    [InlineData("404", true)]
    [InlineData("Minimal", false)]
    [InlineData("none", false)]
    [InlineData("", false)]
    public void UnsetMetadataHandlerMustBeAKnownValue(string value, bool valid)
    {
        var result = new RefresherOptionsValidator().Validate(null, new RefresherOptions { IssuerUrl = TestHost.IssuerUrl, UnsetMetadataHandler = value });
        Assert.Equal(valid, result.Succeeded);
    }

    [Fact]
    public async Task BrokenBlockDoesNotFallBackToBasicDataOrGetAppendedTo()
    {
        const string Broken = "#proof-metadata-begin\nuser-data: !secret typo\n#proof-metadata-end\n";
        var vm = vms.Add("web01", BiosGuid, Broken);
        var read = await Get(vm);
        Assert.Equal(MetadataResponseStatus.Invalid, read.Status);
        Assert.Null(read.InstanceId);
        Assert.Equal(MetadataResponseStatus.Invalid, (await Finish(vm, ProvisioningStatus.Complete)).Status);
        Assert.Equal(Broken, vms.Notes(vm));
    }

    [Fact]
    public async Task EachVmGetsItsOwnNotesAndInstanceIdFromItsBiosGuid()
    {
        var a = vms.Add("a", BiosGuid, Enrolled("user-data: for-a\n"));
        var b = vms.Add("b", Guid.NewGuid(), Enrolled("user-data: for-b\n"));

        var response = await Get(a);
        Assert.Equal(InstanceId, response.InstanceId);
        Assert.Equal("for-a", response.UserData);
        Assert.Equal("a", response.MetaData!.Value.GetProperty("local-hostname").GetString());
        Assert.Equal("for-b", (await Get(b)).UserData);
    }

    [Fact]
    public async Task CopiesWithTheSameBiosGuidShareAnInstanceIdAndANewGuidChangesIt()
    {
        var original = vms.Add("original", BiosGuid, Enrolled(""));
        var copy = vms.Add("copy", BiosGuid, Enrolled(""));
        Assert.Equal((await Get(original)).InstanceId, (await Get(copy)).InstanceId);

        vms.SetBiosGuid(copy, Guid.NewGuid());
        Assert.NotEqual((await Get(original)).InstanceId, (await Get(copy)).InstanceId);
    }

    [Theory]
    [InlineData("web-01", "web-01")]
    [InlineData("has space", null)]
    [InlineData("-bad", null)]
    [InlineData("web.corp", null)]
    public void DefaultHostnameIsTheVmNameIfItCanBeOne(string name, string? expected) =>
        Assert.Equal(expected, MetadataRequestHandler.HostnameFrom(name));

    [Fact]
    public async Task FinishClearsThenSensitiveValuesAreNotServedAndRepeatsDoNotWrite()
    {
        var vm = vms.Add("web01", BiosGuid, "Keep me.\n" + Enrolled("user-data: !sensitive hunter2\n"));
        Assert.Equal("hunter2", (await Get(vm)).UserData);

        var finished = await Finish(vm, ProvisioningStatus.Complete);

        Assert.Equal(ProvisioningStatus.Complete, finished.Provisioning);
        Assert.DoesNotContain("hunter2", vms.Notes(vm));
        Assert.StartsWith("Keep me.\n", vms.Notes(vm));
        Assert.Contains($"instance-id: {InstanceId}", vms.Notes(vm));
        Assert.Null((await Get(vm)).UserData);
        Assert.Equal(1, vms.Writes);

        // cloud-init's phone_home may retry, and a later report does not change what was recorded.
        var again = await Finish(vm, ProvisioningStatus.Failed);
        Assert.Equal(ProvisioningStatus.Complete, again.Provisioning);
        Assert.Equal(1, vms.Writes);
    }

    [Theory]
    [InlineData("get-everything", null)]
    [InlineData(MetadataOperations.Finish, null)]
    [InlineData(MetadataOperations.Finish, "pending")]
    [InlineData(MetadataOperations.Finish, "complete\nuser-data: injected")]
    public async Task RequestsThatAreNotUnderstoodChangeNothing(string op, string? result)
    {
        var vm = vms.Add("web01", BiosGuid, Enrolled("user-data: !sensitive a\n"));
        var response = await handler.HandleAsync(vm, new MetadataRequest(op, result), CancellationToken.None);
        Assert.Equal(MetadataResponseStatus.Invalid, response.Status);
        Assert.Equal(0, vms.Writes);
    }

    [Fact]
    public async Task UnusableBlockIsInvalidAndNothingIsServed()
    {
        var vm = vms.Add("web01", BiosGuid, Enrolled("bogus: hunter2\n"));
        var response = await Get(vm);
        Assert.Equal(MetadataResponseStatus.Invalid, response.Status);
        Assert.Null(response.MetaData);
    }

    [Fact]
    public async Task HyperVFailureIsUnavailableAndNotAFalseSuccess()
    {
        var vm = vms.Add("web01", BiosGuid, Enrolled("user-data: !sensitive a\n"));
        vms.FailWrites = true;
        Assert.Equal(MetadataResponseStatus.Unavailable, (await Finish(vm, ProvisioningStatus.Complete)).Status);
        Assert.Contains("!sensitive", vms.Notes(vm));
    }

    [Fact]
    public async Task ConnectionCarriesOneRequestAndOneResponse()
    {
        var vm = vms.Add("web01", BiosGuid, Enrolled("user-data: mine\n"));
        var input = new MemoryStream();
        await MetadataFraming.WriteAsync(input, new MetadataRequest(MetadataOperations.Get), MetadataJsonContext.Default.MetadataRequest, CancellationToken.None);
        input.Position = 0;
        var socket = new DuplexStream(input);

        await NewServer().HandleConnectionAsync(socket, vm, CancellationToken.None);

        socket.Written.Position = 0;
        var response = await MetadataFraming.ReadAsync(socket.Written, MetadataService.MaxResponseLength, MetadataJsonContext.Default.MetadataResponse, CancellationToken.None);
        Assert.Equal("mine", response.UserData);
    }

    [Theory]
    [InlineData(int.MaxValue)]
    [InlineData(MetadataService.MaxRequestLength + 1)]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task OversizedFramesAreRefusedBeforeReading(int length)
    {
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, length);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            NewServer().HandleConnectionAsync(new DuplexStream(new MemoryStream(header)), Guid.NewGuid(), CancellationToken.None));
    }

    [Fact]
    public async Task GarbageIsRefused()
    {
        var body = Encoding.UTF8.GetBytes("not json");
        var frame = new byte[4 + body.Length];
        BinaryPrimitives.WriteInt32LittleEndian(frame, body.Length);
        body.CopyTo(frame, 4);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            NewServer().HandleConnectionAsync(new DuplexStream(new MemoryStream(frame)), Guid.NewGuid(), CancellationToken.None));
    }

    [Fact]
    public async Task PartialFrameIsRefused() =>
        await Assert.ThrowsAsync<EndOfStreamException>(() =>
            NewServer().HandleConnectionAsync(new DuplexStream(new MemoryStream([1, 0])), Guid.NewGuid(), CancellationToken.None));

    [Fact]
    public void RateLimitIsPerVmAndResetsAfterTheWindow()
    {
        var time = new ManualTime(new DateTimeOffset(2026, 10, 31, 0, 0, 0, TimeSpan.Zero));
        var limiter = new VmRateLimiter(time);
        var (noisy, quiet) = (Guid.NewGuid(), Guid.NewGuid());
        for (var i = 0; i < VmRateLimiter.MaxRequests; i++)
        {
            Assert.True(limiter.TryAcquire(noisy));
        }

        Assert.False(limiter.TryAcquire(noisy));
        Assert.True(limiter.TryAcquire(quiet));
        time.Advance(VmRateLimiter.Window);
        Assert.True(limiter.TryAcquire(noisy));
    }

    [Fact]
    public void ServiceIdIsTheVsockTemplateForThePort()
    {
        var bytes = MetadataService.ServiceId.ToByteArray();
        Assert.Equal(MetadataService.VsockPort, BinaryPrimitives.ReadUInt32LittleEndian(bytes));
        // Linux connects with a port, and Hyper-V turns it into a GUID with this template (Microsoft's documentation).
        Assert.EndsWith("-facb-11e6-bd58-64006a7986d3", MetadataService.ServiceId.ToString("D"));
    }

    [Fact]
    public void EndPointHasTheLayoutOfSockaddrHv()
    {
        var (vm, service) = (Guid.NewGuid(), Guid.NewGuid());
        var address = new HyperVEndPoint(vm, service).Serialize();
        Assert.Equal(36, address.Size);
        Assert.Equal(HyperVEndPoint.Family, address.Family);
        Assert.Equal(vm, new Guid(address.Buffer.Span.Slice(4, 16)));
        Assert.Equal(service, new Guid(address.Buffer.Span.Slice(20, 16)));

        var parsed = (HyperVEndPoint)new HyperVEndPoint(Guid.Empty, Guid.Empty).Create(address);
        Assert.Equal(vm, parsed.VmId);
        Assert.Equal(service, parsed.ServiceId);
        Assert.Equal((AddressFamily)34, parsed.AddressFamily);
    }

    [Theory]
    [InlineData("a\r\nb", "a&#13;\nb")]
    [InlineData("a\nb", "a\nb")]
    [InlineData("<a> & b", "&lt;a&gt; &amp; b")]
    public void NotesAreEscapedSoTheyReadBackExactly(string notes, string expected)
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("WMI.");
            return;
        }

        Assert.Equal(expected, WmiHyperVHost.EscapeForWmiText(notes));
    }

    [Fact]
    public async Task HyperVSocketConnectReachesTheNetworkLayer()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "AF_HYPERV.");

        // HV_GUID_LOOPBACK and a service nothing listens on: refused. Before the socket was bound first, ConnectEx said
        // invalid argument here and on every real guest.
        var nobody = new HyperVEndPoint(new Guid("e0e16197-dd56-4a10-9195-5ee7a155a838"), Guid.NewGuid());
        var ex = await Assert.ThrowsAsync<SocketException>(() => Proof.Metadata.HyperVSocketChannel.ConnectHyperVAsync(nobody, CancellationToken.None));
        Assert.Equal(SocketError.ConnectionRefused, ex.SocketErrorCode);
    }

    private MetadataServer NewServer() => new(
        handler,
        Options.Create(new RefresherOptions { IssuerUrl = TestHost.IssuerUrl }),
        TimeProvider.System,
        NullLogger<MetadataServer>.Instance);

    /// <summary>Reads from one stream and writes to another, as a socket does.</summary>
    private sealed class DuplexStream(Stream input) : Stream
    {
        public MemoryStream Written { get; } = new();

        public override bool CanRead => true;

        public override bool CanWrite => true;

        public override bool CanSeek => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => input.Read(buffer, offset, count);

        public override void Write(byte[] buffer, int offset, int count) => Written.Write(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
