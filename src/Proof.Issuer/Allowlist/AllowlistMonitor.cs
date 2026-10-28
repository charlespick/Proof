using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace Proof.Issuer.Allowlist;

/// <summary>
/// Holds the current allowlist and reloads it when the file changes. Polls rather than using a file watcher,
/// because a ConfigMap update is a symlink swap that watchers report unreliably. A file that fails validation
/// is refused: the previous list stays in force and the failure is logged and counted.
/// </summary>
public sealed class AllowlistMonitor(
    IOptions<IssuerOptions> options,
    TimeProvider time,
    IssuerMetrics metrics,
    ILogger<AllowlistMonitor> logger) : BackgroundService
{
    private readonly Lock reloadLock = new();
    private volatile HostAllowlist? current;
    private string? lastSeenSha256;

    /// <summary>The list in force, or null until a valid file has been loaded. Readiness depends on it.</summary>
    public HostAllowlist? Current => current;

    /// <summary>True if the file on disk was valid the last time it was read.</summary>
    public bool LastReadSucceeded { get; private set; }

    /// <summary>Reads the file and swaps in a new list if its content changed and is valid.</summary>
    public void Reload()
    {
        lock (reloadLock)
        {
            var path = options.Value.AllowlistPath;
            byte[] content;
            try
            {
                content = File.ReadAllBytes(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Refuse($"cannot read {path}: {ex.Message}", sha256: null);
                return;
            }

            var sha256 = Convert.ToHexStringLower(SHA256.HashData(content));
            if (sha256 == lastSeenSha256)
            {
                return;
            }

            try
            {
                var list = AllowlistParser.Parse(content);
                current = list;
                lastSeenSha256 = sha256;
                LastReadSucceeded = true;
                logger.LogInformation(
                    "Loaded host allowlist {Sha256}: {HostCount} hosts, {KeyCount} keys",
                    list.Sha256, list.HostCount, list.Keys.Count);
            }
            catch (AllowlistException ex)
            {
                Refuse(ex.Message, sha256);
            }
        }
    }

    /// <summary>Loads the first list before the host starts serving. From .NET 10, ExecuteAsync runs only after startup.</summary>
    public override Task StartAsync(CancellationToken cancellationToken)
    {
        Reload();
        return base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(options.Value.AllowlistPollInterval, time, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            Reload();
        }
    }

    private void Refuse(string reason, string? sha256)
    {
        // Remember a bad file's hash so it is reported once, not on every poll.
        lastSeenSha256 = sha256;
        LastReadSucceeded = false;
        metrics.AllowlistReloadFailed();
        logger.LogError(
            "Refused host allowlist {Sha256}; {Keeping}. Reason: {Reason}",
            sha256, current is null ? "no list is loaded" : $"keeping {current.Sha256}", reason);
    }
}
