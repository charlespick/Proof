using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Proof.Shared;

namespace Proof.Metadata;

/// <summary>The VM's channel to its Hyper-V host. Faked in tests.</summary>
public interface IHostChannel
{
    /// <exception cref="IOException">The host cannot be reached. It may not run Proof, or this may not be a Hyper-V guest.</exception>
    Task<MetadataResponse> SendAsync(MetadataRequest request, CancellationToken cancellationToken);
}

/// <summary>
/// One connection per request, over Hyper-V sockets: AF_HYPERV on Windows, AF_VSOCK on Linux. A connection needs no
/// credentials: the hypervisor tells the host which VM it came from.
/// </summary>
public sealed class HyperVSocketChannel : IHostChannel
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    public async Task<MetadataResponse> SendAsync(MetadataRequest request, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Timeout);
        try
        {
            await using var stream = await ConnectAsync(timeout.Token);
            await MetadataFraming.WriteAsync(stream, request, MetadataJsonContext.Default.MetadataRequest, timeout.Token);
            return await MetadataFraming.ReadAsync(stream, MetadataService.MaxResponseLength, MetadataJsonContext.Default.MetadataResponse, timeout.Token);
        }
        catch (Exception ex) when (ex is SocketException or InvalidDataException or EndOfStreamException
            || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            throw new IOException($"Cannot reach the Hyper-V host's metadata service: {ex.Message}", ex);
        }
    }

    private static async Task<Stream> ConnectAsync(CancellationToken cancellationToken)
    {
        return OperatingSystem.IsWindows()
            ? new NetworkStream(await ConnectHyperVAsync(new HyperVEndPoint(HyperVEndPoint.Parent, MetadataService.ServiceId), cancellationToken), ownsSocket: true)
            : await Task.Run<Stream>(() => VsockStream.ConnectToHost(MetadataService.VsockPort, Timeout), cancellationToken);
    }

    /// <summary>
    /// A connected AF_HYPERV socket. An async connect is ConnectEx, which fails with "invalid argument" on an unbound
    /// socket, and .NET binds one for you only for IP. Binding to the zero address picks whatever the system would.
    /// </summary>
    public static async Task<Socket> ConnectHyperVAsync(HyperVEndPoint endPoint, CancellationToken cancellationToken)
    {
        var socket = new Socket(HyperVEndPoint.Family, SocketType.Stream, HyperVEndPoint.Protocol);
        try
        {
            socket.Bind(new HyperVEndPoint(Guid.Empty, Guid.Empty));
            await socket.ConnectAsync(endPoint, cancellationToken);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}

/// <summary>
/// A connected AF_VSOCK socket on a Linux guest, which is how Hyper-V sockets look there (the <c>hv_sock</c> module).
/// .NET's Socket cannot create or address this family, so this calls libc directly. Calls block, with kernel timeouts
/// on the socket, and the base class runs them on the thread pool for the async methods.
/// </summary>
internal sealed partial class VsockStream : Stream
{
    private const int AfVsock = 40;
    private const int SockStream = 1;
    private const int SolSocket = 1;
    private const int SoRcvTimeo = 20;
    private const int SoSndTimeo = 21;
    private const uint VmAddrCidHost = 2;
    private const int Eintr = 4;

    private readonly SafeFileHandle handle;

    private VsockStream(SafeFileHandle handle) => this.handle = handle;

    public static VsockStream ConnectToHost(uint port, TimeSpan timeout)
    {
        var fd = socket(AfVsock, SockStream, 0);
        if (fd < 0)
        {
            throw new IOException($"Cannot create an AF_VSOCK socket (errno {Marshal.GetLastPInvokeError()}). The hv_sock kernel module may not be loaded.");
        }

        var handle = new SafeFileHandle(fd, ownsHandle: true);
        try
        {
            var limit = new TimeVal { Seconds = (long)timeout.TotalSeconds };
            setsockopt(handle, SolSocket, SoRcvTimeo, ref limit, Marshal.SizeOf<TimeVal>());
            setsockopt(handle, SolSocket, SoSndTimeo, ref limit, Marshal.SizeOf<TimeVal>());

            var address = new SockAddrVm { Family = AfVsock, Port = port, Cid = VmAddrCidHost };
            if (connect(handle, ref address, Marshal.SizeOf<SockAddrVm>()) != 0)
            {
                throw new IOException($"Cannot connect to the host over AF_VSOCK (errno {Marshal.GetLastPInvokeError()}).");
            }

            return new VsockStream(handle);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

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

    public override int Read(byte[] buffer, int offset, int count)
    {
        while (true)
        {
            var read = read_(handle, ref buffer[offset], count);
            if (read >= 0)
            {
                return (int)read;
            }

            if (Marshal.GetLastPInvokeError() != Eintr)
            {
                throw new IOException($"AF_VSOCK read failed (errno {Marshal.GetLastPInvokeError()}).");
            }
        }
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        while (count > 0)
        {
            var written = write_(handle, ref buffer[offset], count);
            if (written >= 0)
            {
                offset += (int)written;
                count -= (int)written;
            }
            else if (Marshal.GetLastPInvokeError() != Eintr)
            {
                throw new IOException($"AF_VSOCK write failed (errno {Marshal.GetLastPInvokeError()}).");
            }
        }
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            handle.Dispose();
        }

        base.Dispose(disposing);
    }

    /// <summary><c>struct sockaddr_vm</c> from linux/vm_sockets.h: 16 bytes.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct SockAddrVm
    {
        public ushort Family;
        public ushort Reserved1;
        public uint Port;
        public uint Cid;
        public uint Zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TimeVal
    {
        public long Seconds;
        public long Microseconds;
    }

    // Named exactly: "libc" alone would probe libc.so, which is absent or a linker script.
    private const string LibC = "libc.so.6";

    [LibraryImport(LibC, SetLastError = true)]
    private static partial int socket(int domain, int type, int protocol);

    [LibraryImport(LibC, SetLastError = true)]
    private static partial int connect(SafeFileHandle fd, ref SockAddrVm address, int length);

    [LibraryImport(LibC, SetLastError = true)]
    private static partial int setsockopt(SafeFileHandle fd, int level, int name, ref TimeVal value, int length);

    [LibraryImport(LibC, EntryPoint = "read", SetLastError = true)]
    private static partial nint read_(SafeFileHandle fd, ref byte buffer, nint count);

    [LibraryImport(LibC, EntryPoint = "write", SetLastError = true)]
    private static partial nint write_(SafeFileHandle fd, ref byte buffer, nint count);
}
