using Microsoft.Extensions.Options;
using Proof.Shared;

namespace Proof.Refresher;

/// <summary>Refresher configuration, bound from the <c>Proof</c> section.</summary>
public sealed class RefresherOptions
{
    public const string SectionName = "Proof";

    /// <summary>The issuer URL, exactly as the issuer is configured. Host tokens carry it as <c>aud</c>.</summary>
    public string IssuerUrl { get; set; } = "";

    /// <summary>This host's ID in the issuer allowlist. Host tokens carry it as <c>iss</c>.</summary>
    public string HostId { get; set; } = Environment.MachineName.ToLowerInvariant();

    /// <summary>The name of the host key in the CNG software key storage provider (machine keys).</summary>
    public string HostKeyName { get; set; } = "Proof Host Key";

    /// <summary>
    /// How often the refresher runs a scheduled pass over all running VMs. VM starts, migrations and identity changes
    /// trigger a pass of their own, so this renews tokens and catches any event that was missed. Tokens are renewed every
    /// <see cref="HostTokenPolicy.RefreshInterval"/>, so a longer scan would let them go stale.
    /// </summary>
    public TimeSpan ScanInterval { get; set; } = HostTokenPolicy.RefreshInterval;

    /// <summary>Serve instance metadata to VMs from their notes. Off, no socket is opened.</summary>
    public bool MetadataEnabled { get; set; } = true;

    /// <summary>
    /// What a VM whose notes have no block gets: one of <see cref="UnsetMetadataHandlers"/>.
    /// </summary>
    public string UnsetMetadataHandler { get; set; } = UnsetMetadataHandlers.Minimal;
}

/// <summary>The values of <see cref="RefresherOptions.UnsetMetadataHandler"/>.</summary>
public static class UnsetMetadataHandlers
{
    /// <summary>
    /// Serve its instance ID and hostname, and record a phone-home by adding a block with only the status. Pointing an
    /// image at <c>proof-metadata</c> is already a choice to use this, and clients get an answer without waiting.
    /// </summary>
    public const string Minimal = "minimal";

    /// <summary>Answer "not found", and record nothing. Cloud-init retries a 404 until its <c>max_wait</c>.</summary>
    public const string NotFound = "404";
}

public sealed class RefresherOptionsValidator : IValidateOptions<RefresherOptions>
{
    public ValidateOptionsResult Validate(string? name, RefresherOptions options)
    {
        var errors = new List<string>();

        if (!ProofIssuerUrl.IsValid(options.IssuerUrl))
        {
            errors.Add("Proof:IssuerUrl must be an absolute https URL with no trailing slash, query or fragment, matching the issuer's.");
        }

        if (!ProofNames.IsValid(options.HostId))
        {
            errors.Add("Proof:HostId must be 1 to 253 letters, digits, '.', '-' or '_', starting with a letter or digit.");
        }

        if (string.IsNullOrWhiteSpace(options.HostKeyName))
        {
            errors.Add("Proof:HostKeyName is required.");
        }

        if (options.ScanInterval < TimeSpan.FromSeconds(1) || options.ScanInterval > HostTokenPolicy.RefreshInterval)
        {
            errors.Add($"Proof:ScanInterval must be between 00:00:01 and {HostTokenPolicy.RefreshInterval}.");
        }

        if (options.UnsetMetadataHandler is not (UnsetMetadataHandlers.Minimal or UnsetMetadataHandlers.NotFound))
        {
            errors.Add($"Proof:UnsetMetadataHandler must be {UnsetMetadataHandlers.Minimal} or {UnsetMetadataHandlers.NotFound}.");
        }

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
