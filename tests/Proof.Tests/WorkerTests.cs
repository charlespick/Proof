using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Proof.Refresher;
using Proof.Tests.Support;

namespace Proof.Tests;

/// <summary>
/// The service loop, with the default 5-minute scan: anything that happens within these tests is driven by
/// start events or the retry delay, never by the schedule.
/// </summary>
public sealed class WorkerTests : IAsyncDisposable
{
    private static readonly VirtualMachine Web01 = new(TestHost.VmId, "web01");
    private static readonly VirtualMachine Db01 = new("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "db01");
    private static readonly TimeSpan Soon = TimeSpan.FromSeconds(5);

    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ServiceProvider services = new ServiceCollection().AddMetrics().BuildServiceProvider();
    private readonly FakeHyperV hyperV = new();
    private Worker? worker;

    private async Task StartWorkerAsync(TimeSpan? retryDelay = null)
    {
        var options = Options.Create(new RefresherOptions { IssuerUrl = TestHost.IssuerUrl, HostId = "hv-host-01" });
        Assert.Equal(TimeSpan.FromMinutes(5), options.Value.ScanInterval);
        var signer = new HostTokenSigner(key, options);
        var refresher = new TokenRefresher(hyperV, signer, TimeProvider.System, services.GetRequiredService<IMeterFactory>(), NullLogger<TokenRefresher>.Instance);
        worker = new Worker(refresher, signer, hyperV, options, TimeProvider.System, NullLogger<Worker>.Instance)
        {
            RetryDelay = retryDelay ?? TimeSpan.FromSeconds(30),
        };
        await worker.StartAsync(CancellationToken.None);
    }

    public async ValueTask DisposeAsync()
    {
        if (worker is not null)
        {
            await worker.StopAsync(CancellationToken.None);
            worker.Dispose();
        }

        services.Dispose();
        key.Dispose();
    }

    private static async Task WaitUntil(Func<bool> condition, string what)
    {
        var deadline = DateTime.UtcNow + Soon;
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, $"Timed out waiting for {what}.");
            await Task.Delay(20);
        }
    }

    private void AddWithoutEvent(VirtualMachine vm)
    {
        lock (hyperV.Running)
        {
            hyperV.Running.Add(vm);
        }
    }

    [Fact]
    public async Task StartedVmIsWrittenWithoutWaitingForScan()
    {
        hyperV.Running.Add(Web01);
        await StartWorkerAsync();
        await WaitUntil(() => hyperV.HasToken(Web01), "the first pass");

        hyperV.Start(Db01);

        await WaitUntil(() => hyperV.HasToken(Db01), "the VM start to trigger a pass");
    }

    [Fact]
    public async Task DroppedSubscriptionIsRenewedAtOnce()
    {
        await StartWorkerAsync();
        await WaitUntil(() => hyperV.Subscriptions == 1, "the first subscription");

        // A VM that starts while the subscription is down is found by the pass that follows the renewal.
        hyperV.Subscription!.Drop();
        AddWithoutEvent(Web01);

        await WaitUntil(() => hyperV.Subscriptions == 2, "the subscription to be renewed");
        await WaitUntil(() => hyperV.HasToken(Web01), "the pass after renewal");
        hyperV.Start(Db01);
        await WaitUntil(() => hyperV.HasToken(Db01), "the renewed subscription to trigger a pass");
    }

    [Fact]
    public async Task FailedWriteIsRetriedBeforeNextScan()
    {
        hyperV.Running.Add(Web01);
        hyperV.Failing.Add(Web01.Id);
        await StartWorkerAsync(retryDelay: TimeSpan.FromMilliseconds(200));
        await WaitUntil(() => hyperV.Writes >= 1, "the first attempt");

        lock (hyperV.Kvp)
        {
            hyperV.Failing.Clear();
        }

        await WaitUntil(() => hyperV.HasToken(Web01), "the retry");
    }

    [Fact]
    public async Task SubscribingIsRetriedAndScanCoversTheGap()
    {
        hyperV.SubscribeFailure = new InvalidOperationException("WMI unavailable");
        await StartWorkerAsync(retryDelay: TimeSpan.FromMilliseconds(200));
        AddWithoutEvent(Db01);
        await WaitUntil(() => hyperV.HasToken(Db01), "a retry pass to find the VM");

        hyperV.SubscribeFailure = null;

        await WaitUntil(() => hyperV.Subscriptions == 1, "subscribing to succeed");
        hyperV.Start(Web01);
        await WaitUntil(() => hyperV.HasToken(Web01), "the new subscription to trigger a pass");
    }
}
