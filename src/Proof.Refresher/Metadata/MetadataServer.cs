using System.Net.Sockets;
using Microsoft.Extensions.Options;
using Proof.Shared;

namespace Proof.Refresher.Metadata;

/// <summary>
/// Listens on the Hyper-V socket for <c>proof-metadata</c> in this host's VMs. Each connection carries one request.
/// Guests are not trusted, so sizes, time and rates are limited. This runs as its own service, without access to the
/// host key, so neither a fault nor a compromise here reaches the token refresher or its key.
/// </summary>
public sealed class MetadataServer(
    MetadataRequestHandler handler, IOptions<RefresherOptions> options, TimeProvider time, ILogger<MetadataServer> logger) : BackgroundService
{
    // Guests send their request as soon as they connect, so this is much shorter than a whole connection may take.
    public static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(5);
    public const int MaxAcceptFailures = 16;

    private static readonly TimeSpan ConnectionTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan RetryDelay = TimeSpan.FromSeconds(30);

    private readonly ConnectionGate gate = new(time);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.MetadataEnabled)
        {
            logger.LogInformation("Instance metadata is turned off by Proof:MetadataEnabled.");
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ListenAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogError("The instance metadata listener failed; retrying in {RetryDelay}. {Error}", RetryDelay, ex.Message);
                await Task.Delay(RetryDelay, time, stoppingToken).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
            }
        }
    }

    private async Task ListenAsync(CancellationToken stoppingToken)
    {
        using var listener = new Socket(HyperVEndPoint.Family, SocketType.Stream, HyperVEndPoint.Protocol);
        listener.Bind(new HyperVEndPoint(HyperVEndPoint.Children, MetadataService.ServiceId));
        listener.Listen(ConnectionGate.MaxConnections);
        logger.LogInformation("Serving instance metadata to VMs on Hyper-V socket service {ServiceId}.", MetadataService.ServiceId);

        while (true)
        {
            var socket = await AcceptNextAsync(cancellationToken => listener.AcceptAsync(cancellationToken), stoppingToken);
            var peer = PeerOf(socket);
            if (peer is not { } vmId || !gate.TryEnter(vmId))
            {
                logger.LogDebug("Refused a metadata connection from VM {VmId}.", peer);
                socket.Dispose();
                continue;
            }

            // Not awaited, so one slow guest cannot hold up the others.
            _ = ServeAsync(socket, vmId, stoppingToken);
        }
    }

    /// <summary>
    /// The next connection. One that fails while it is accepted is dropped, because the others are not affected. Other
    /// errors may mean the listener itself is broken, so enough of them in a row are left for the caller to handle.
    /// </summary>
    public async Task<T> AcceptNextAsync<T>(Func<CancellationToken, ValueTask<T>> accept, CancellationToken cancellationToken)
    {
        var failures = 0;
        while (true)
        {
            try
            {
                return await accept(cancellationToken);
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted || ++failures < MaxAcceptFailures)
            {
                logger.LogDebug("A metadata connection could not be accepted: {Error}", ex.Message);
            }
        }
    }

    private static Guid? PeerOf(Socket socket)
    {
        try
        {
            return socket.RemoteEndPoint is HyperVEndPoint peer ? peer.VmId : null;
        }
        catch (SocketException)
        {
            return null;
        }
    }

    private async Task ServeAsync(Socket socket, Guid vmId, CancellationToken stoppingToken)
    {
        try
        {
            using (socket)
            {
                await using var stream = new NetworkStream(socket, ownsSocket: false);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                timeout.CancelAfter(ConnectionTimeout);
                await HandleConnectionAsync(stream, vmId, timeout.Token);
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or InvalidDataException or OperationCanceledException or ObjectDisposedException)
        {
            // A guest that hung up, stalled or sent rubbish. It affects only that guest.
            logger.LogDebug("A metadata connection ended early: {Error}", ex.Message);
        }
        finally
        {
            gate.Leave(vmId);
        }
    }

    /// <summary>One request and its response. <paramref name="vmId"/> must come from the socket, never from the guest.</summary>
    public async Task HandleConnectionAsync(Stream stream, Guid vmId, CancellationToken cancellationToken)
    {
        using var deadline = new CancellationTokenSource(RequestTimeout, time);
        using var read = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        var request = await MetadataFraming.ReadAsync(stream, MetadataService.MaxRequestLength, MetadataJsonContext.Default.MetadataRequest, read.Token);
        var response = await handler.HandleAsync(vmId, request, cancellationToken);
        await MetadataFraming.WriteAsync(stream, response, MetadataJsonContext.Default.MetadataResponse, cancellationToken);
    }
}

/// <summary>
/// Decides whether to serve a connection as soon as it is accepted, before the guest has to send anything, so that no
/// VM can hold more than its share of the host's connections. A VM's <c>proof-metadata</c> makes one request at a time,
/// so its limit bounds only a VM that misbehaves.
/// </summary>
public sealed class ConnectionGate(TimeProvider time)
{
    public const int MaxConnections = 64;
    public const int MaxConnectionsPerVm = 4;

    private readonly VmRateLimiter limiter = new(time);
    private readonly Dictionary<Guid, int> open = [];
    private int total;

    /// <summary>Whether to serve a connection from this VM. If so, call <see cref="Leave"/> when it ends.</summary>
    public bool TryEnter(Guid vmId)
    {
        lock (open)
        {
            var count = open.GetValueOrDefault(vmId);
            if (count >= MaxConnectionsPerVm || !limiter.TryAcquire(vmId) || total >= MaxConnections)
            {
                return false;
            }

            open[vmId] = count + 1;
            total++;
            return true;
        }
    }

    public void Leave(Guid vmId)
    {
        lock (open)
        {
            total--;
            if (open[vmId] == 1)
            {
                open.Remove(vmId);
            }
            else
            {
                open[vmId]--;
            }
        }
    }
}

/// <summary>
/// Connections per VM per window, because each one's request reads the VM's settings over WMI. The guest keeps its last
/// answer for a few seconds, so a boot's many paths are a handful of requests, and this bounds only a VM that misbehaves.
/// </summary>
public sealed class VmRateLimiter(TimeProvider time)
{
    public const int MaxRequests = 120;
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(1);

    private readonly Dictionary<Guid, (DateTimeOffset Start, int Count)> windows = [];

    public bool TryAcquire(Guid vmId)
    {
        var now = time.GetUtcNow();
        lock (windows)
        {
            // Only VMs that have connected are here, so this stays small. A finished window starts again.
            foreach (var idle in windows.Where(w => now - w.Value.Start >= Window).Select(w => w.Key).ToList())
            {
                windows.Remove(idle);
            }

            var (start, count) = windows.GetValueOrDefault(vmId, (now, 0));
            if (count >= MaxRequests)
            {
                return false;
            }

            windows[vmId] = (start, count + 1);
            return true;
        }
    }
}
