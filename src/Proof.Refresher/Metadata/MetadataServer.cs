using System.Net.Sockets;
using Microsoft.Extensions.Options;
using Proof.Shared;

namespace Proof.Refresher.Metadata;

/// <summary>
/// Listens on the Hyper-V socket for <c>proof-metadata</c> in this host's VMs. Each connection carries one request.
/// Guests are not trusted, so sizes, time and rates are limited, and a failure here never touches the token refresher.
/// </summary>
public sealed class MetadataServer(
    MetadataRequestHandler handler, IOptions<RefresherOptions> options, TimeProvider time, ILogger<MetadataServer> logger) : BackgroundService
{
    private const int MaxConcurrentConnections = 64;
    private static readonly TimeSpan ConnectionTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan RetryDelay = TimeSpan.FromSeconds(30);

    private readonly SemaphoreSlim connections = new(MaxConcurrentConnections, MaxConcurrentConnections);
    private readonly VmRateLimiter limiter = new(time);

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
        listener.Listen(MaxConcurrentConnections);
        logger.LogInformation("Serving instance metadata to VMs on Hyper-V socket service {ServiceId}.", MetadataService.ServiceId);

        while (true)
        {
            var socket = await listener.AcceptAsync(stoppingToken);
            if (!connections.Wait(0))
            {
                socket.Dispose();
                continue;
            }

            // Not awaited, so one slow guest cannot hold up the others.
            _ = ServeAsync(socket, stoppingToken);
        }
    }

    private async Task ServeAsync(Socket socket, CancellationToken stoppingToken)
    {
        try
        {
            using (socket)
            {
                if (socket.RemoteEndPoint is not HyperVEndPoint peer)
                {
                    return;
                }

                await using var stream = new NetworkStream(socket, ownsSocket: false);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                timeout.CancelAfter(ConnectionTimeout);
                await HandleConnectionAsync(stream, peer.VmId, timeout.Token);
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or InvalidDataException or OperationCanceledException or ObjectDisposedException)
        {
            // A guest that hung up, stalled or sent rubbish. It affects only that guest.
            logger.LogDebug("A metadata connection ended early: {Error}", ex.Message);
        }
        finally
        {
            connections.Release();
        }
    }

    /// <summary>One request and its response. <paramref name="vmId"/> must come from the socket, never from the guest.</summary>
    public async Task HandleConnectionAsync(Stream stream, Guid vmId, CancellationToken cancellationToken)
    {
        var request = await MetadataFraming.ReadAsync(stream, MetadataService.MaxRequestLength, MetadataJsonContext.Default.MetadataRequest, cancellationToken);
        var response = limiter.TryAcquire(vmId)
            ? await handler.HandleAsync(vmId, request, cancellationToken)
            : new MetadataResponse(MetadataResponseStatus.Unavailable);
        await MetadataFraming.WriteAsync(stream, response, MetadataJsonContext.Default.MetadataResponse, cancellationToken);
    }
}

/// <summary>
/// Requests per VM per window, because each one reads the VM's settings over WMI. The guest keeps its last answer for
/// a few seconds, so a boot's many paths are a handful of requests, and this bounds only a VM that misbehaves.
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
