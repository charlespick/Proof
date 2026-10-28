using System.Threading.Channels;
using Microsoft.Extensions.Options;

namespace Proof.Refresher;

/// <summary>
/// Runs a refresh pass at start, whenever Hyper-V reports a VM starting or migrating in, and on a fixed schedule
/// every <see cref="RefresherOptions.ScanInterval"/>. Event passes do not move the schedule. The schedule renews
/// tokens and catches starts whose events were missed; after a failure the next pass comes sooner.
/// </summary>
public sealed class Worker(
    TokenRefresher refresher, HostTokenSigner signer, IHyperVHost hyperV, IOptions<RefresherOptions> options, TimeProvider time, ILogger<Worker> logger)
    : BackgroundService
{
    // One pending wake-up is enough: a pass covers every running VM, so a burst of starts coalesces into it.
    private readonly Channel<bool> wake = Channel.CreateBounded<bool>(new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropWrite });
    private IVmStartSubscription? subscription;
    private bool subscriptionFailureLogged;

    /// <summary>How soon to try again after a failed write, a failed pass or a lost subscription.</summary>
    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromSeconds(30);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var o = options.Value;
        logger.LogInformation(
            "Refresher started for host {HostId} (cluster {Cluster}), key {Kid}, audience {IssuerUrl}, scanning every {ScanInterval}.",
            o.HostId, o.Cluster ?? "none", signer.Kid, o.IssuerUrl, o.ScanInterval);

        var nextScan = time.GetUtcNow();
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                // Subscribe before the pass, so a VM that starts during it still wakes the next one.
                var subscribed = EnsureSubscribed();

                var now = time.GetUtcNow();
                if (now >= nextScan)
                {
                    // Fixed schedule; if passes fell behind (the machine slept), start again from now.
                    nextScan += o.ScanInterval;
                    if (nextScan <= now)
                    {
                        nextScan = now + o.ScanInterval;
                    }
                }

                var healthy = await RunPassAsync(stoppingToken) && subscribed;

                now = time.GetUtcNow();
                var wakeAt = healthy ? nextScan : Min(nextScan, now + RetryDelay);
                await WaitAsync(wakeAt - now, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            subscription?.Dispose();
        }
    }

    /// <summary>False if the pass failed or any write in it did.</summary>
    private async Task<bool> RunPassAsync(CancellationToken stoppingToken)
    {
        try
        {
            var pass = await refresher.RefreshAsync(stoppingToken);
            if (pass.Written > 0 || pass.Failed > 0)
            {
                logger.LogInformation(
                    "Refresh pass: {Running} running VMs, {Written} tokens written, {Failed} failed.", pass.Running, pass.Written, pass.Failed);
            }

            return pass.Failed == 0;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !stoppingToken.IsCancellationRequested)
        {
            // Listing VMs failed (VMMS restarting, WMI unavailable). Keep the service up and try again.
            logger.LogError(ex, "Refresh pass failed; retrying in {RetryDelay}.", RetryDelay);
            return false;
        }
    }

    /// <summary>Waits for <paramref name="delay"/> or a wake-up, whichever is first.</summary>
    private async Task WaitAsync(TimeSpan delay, CancellationToken stoppingToken)
    {
        if (delay > TimeSpan.Zero)
        {
            using var waitCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            var timeout = Task.Delay(delay, time, waitCts.Token);
            var woken = wake.Reader.WaitToReadAsync(waitCts.Token).AsTask();
            await Task.WhenAny(timeout, woken);
            waitCts.Cancel();
        }

        stoppingToken.ThrowIfCancellationRequested();
        wake.Reader.TryRead(out _);
    }

    /// <summary>True if a subscription is active after the call.</summary>
    private bool EnsureSubscribed()
    {
        if (subscription is { IsActive: true })
        {
            return true;
        }

        var renewing = subscription is not null;
        subscription?.Dispose();
        subscription = null;
        try
        {
            subscription = hyperV.WatchVmStarts(OnVmStarted, OnSubscriptionStopped);
            if (renewing || subscriptionFailureLogged)
            {
                logger.LogInformation("Watching for VM starts again.");
            }

            subscriptionFailureLogged = false;
            return true;
        }
        catch (Exception ex)
        {
            if (!subscriptionFailureLogged)
            {
                logger.LogWarning(ex, "Cannot watch for VM starts; new VMs wait for the next pass. Retrying every {RetryDelay}.", RetryDelay);
                subscriptionFailureLogged = true;
            }

            return false;
        }
    }

    private void OnVmStarted(VirtualMachine vm)
    {
        logger.LogDebug("VM {VmId} ({VmName}) started or migrated in; refreshing now.", vm.Id, vm.Name);
        wake.Writer.TryWrite(true);
    }

    private void OnSubscriptionStopped()
    {
        logger.LogWarning("The VM start subscription ended; renewing it.");
        wake.Writer.TryWrite(true);
    }

    private static DateTimeOffset Min(DateTimeOffset a, DateTimeOffset b) => a < b ? a : b;
}
