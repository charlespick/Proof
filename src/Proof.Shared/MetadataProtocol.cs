using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace Proof.Shared;

/// <summary>
/// The Hyper-V socket service between <c>proof-metadata</c> in a VM and <c>proof-refresher</c> on its host
/// (Design.md 16). The hypervisor names the calling VM to the host, so a request carries no identity.
/// </summary>
public static class MetadataService
{
    /// <summary>The port a Linux guest connects to over AF_VSOCK: "PROF" in ASCII.</summary>
    public const uint VsockPort = 0x50524F46;

    /// <summary>
    /// The service ID a Windows guest connects to, which the host registers and listens on. Linux guests address
    /// services by port, and Hyper-V maps a port to a GUID with this template, so one ID serves both.
    /// </summary>
    public static readonly Guid ServiceId = new("50524f46-facb-11e6-bd58-64006a7986d3");

    public const string ServiceName = "Proof Instance Metadata";

    /// <summary>The largest request a host reads. Requests are small and come from the guest, so they are not trusted.</summary>
    public const int MaxRequestLength = 1024;

    /// <summary>The largest response a guest reads.</summary>
    public const int MaxResponseLength = 4 * 1024 * 1024;
}

public static class MetadataOperations
{
    public const string Get = "get";
    public const string Finish = "finish";
}

public static class ProvisioningStatus
{
    public const string Pending = "pending";
    public const string Complete = "complete";
    public const string Failed = "failed";

    /// <summary>The VM's notes hold no block, so there is no status to report.</summary>
    public const string None = "none";

    public static bool IsFinishResult(string? value) => value is Complete or Failed;
}

public static class MetadataResponseStatus
{
    public const string Ok = "ok";

    /// <summary>The caller is not a VM of this host, or its notes hold no block and the host requires one.</summary>
    public const string NotEnrolled = "not-enrolled";

    /// <summary>The VM's metadata block cannot be used. The host's log says why.</summary>
    public const string Invalid = "invalid";

    /// <summary>Too many requests, or the host could not read or write the VM's settings. Retry later.</summary>
    public const string Unavailable = "unavailable";
}

/// <param name="Op">One of <see cref="MetadataOperations"/>.</param>
/// <param name="Result">For <see cref="MetadataOperations.Finish"/>: complete or failed.</param>
public sealed record MetadataRequest(string Op, string? Result = null);

/// <param name="Status">One of <see cref="MetadataResponseStatus"/>. The other members are set only when it is ok.</param>
/// <param name="InstanceId">The EC2-style instance ID, from the VM's BIOS GUID.</param>
/// <param name="Provisioning">One of <see cref="ProvisioningStatus"/>.</param>
/// <param name="MetaData">The meta-data tree: objects, arrays and strings.</param>
/// <param name="UserData">The user data, if there is any to serve.</param>
public sealed record MetadataResponse(
    string Status, string? InstanceId = null, string? Provisioning = null, JsonElement? MetaData = null, string? UserData = null);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(MetadataRequest))]
[JsonSerializable(typeof(MetadataResponse))]
public sealed partial class MetadataJsonContext : JsonSerializerContext;

/// <summary>A message on the socket: a 32-bit little-endian length, then that many bytes of UTF-8 JSON.</summary>
public static class MetadataFraming
{
    public static async Task WriteAsync<T>(Stream stream, T message, JsonTypeInfo<T> type, CancellationToken cancellationToken)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(message, type);
        var frame = new byte[sizeof(int) + body.Length];
        BinaryPrimitives.WriteInt32LittleEndian(frame, body.Length);
        body.CopyTo(frame, sizeof(int));
        await stream.WriteAsync(frame, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    /// <exception cref="InvalidDataException">The message is over <paramref name="maxLength"/> or is not valid.</exception>
    /// <exception cref="EndOfStreamException">The other side closed the connection part way.</exception>
    public static async Task<T> ReadAsync<T>(Stream stream, int maxLength, JsonTypeInfo<T> type, CancellationToken cancellationToken)
    {
        var header = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(header, cancellationToken);
        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > maxLength)
        {
            throw new InvalidDataException($"A message of {length} bytes is outside the limit of {maxLength}.");
        }

        var body = new byte[length];
        await stream.ReadExactlyAsync(body, cancellationToken);
        try
        {
            return JsonSerializer.Deserialize(body, type) ?? throw new InvalidDataException("The message is null.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("The message is not valid JSON.", ex);
        }
    }
}

/// <summary>A Hyper-V socket address (<c>SOCKADDR_HV</c>): a VM ID and a service ID. .NET has no type of its own for it.</summary>
public sealed class HyperVEndPoint(Guid vmId, Guid serviceId) : EndPoint
{
    /// <summary><c>AF_HYPERV</c>.</summary>
    public const AddressFamily Family = (AddressFamily)34;

    /// <summary><c>HV_PROTOCOL_RAW</c>.</summary>
    public const ProtocolType Protocol = (ProtocolType)1;

    /// <summary><c>HV_GUID_CHILDREN</c>: listen for this host's VMs.</summary>
    public static readonly Guid Children = new("90db8b89-0d35-4f79-8ce9-49ea0ac8b7cd");

    /// <summary><c>HV_GUID_PARENT</c>: connect from a VM to its host.</summary>
    public static readonly Guid Parent = new("a42e7cda-d03f-480c-9cc2-a4de20abb878");

    // Family and reserved, 2 bytes each, then the two GUIDs in their usual mixed-endian layout.
    private const int VmIdOffset = 4;
    private const int ServiceIdOffset = 20;
    private const int Length = 36;

    public Guid VmId { get; } = vmId;

    public Guid ServiceId { get; } = serviceId;

    public override AddressFamily AddressFamily => Family;

    public override SocketAddress Serialize()
    {
        var address = new SocketAddress(Family, Length);
        var buffer = address.Buffer.Span;
        VmId.TryWriteBytes(buffer[VmIdOffset..]);
        ServiceId.TryWriteBytes(buffer[ServiceIdOffset..]);
        return address;
    }

    public override EndPoint Create(SocketAddress socketAddress)
    {
        var buffer = socketAddress.Buffer.Span;
        return new HyperVEndPoint(new Guid(buffer.Slice(VmIdOffset, 16)), new Guid(buffer.Slice(ServiceIdOffset, 16)));
    }

    public override string ToString() => $"{VmId:D}:{ServiceId:D}";
}
