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

    /// <summary>The cluster this host belongs to, as in its allowlist entry. Omit for a standalone host.</summary>
    public string? Cluster { get; set; }

    /// <summary>The name of the host key in the CNG software key storage provider (machine keys).</summary>
    public string HostKeyName { get; set; } = "Proof Host Key";

    /// <summary>
    /// How often the refresher runs a scheduled pass over all running VMs. VM starts and migrations trigger a pass
    /// of their own, so this renews tokens and catches any start event that was missed. Tokens are renewed every
    /// <see cref="HostTokenPolicy.RefreshInterval"/>, so a longer scan would let them go stale.
    /// </summary>
    public TimeSpan ScanInterval { get; set; } = HostTokenPolicy.RefreshInterval;
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

        if (options.Cluster is not null && !ProofNames.IsValid(options.Cluster))
        {
            errors.Add("Proof:Cluster must be 1 to 253 letters, digits, '.', '-' or '_', starting with a letter or digit; omit it for a standalone host.");
        }

        if (string.IsNullOrWhiteSpace(options.HostKeyName))
        {
            errors.Add("Proof:HostKeyName is required.");
        }

        if (options.ScanInterval < TimeSpan.FromSeconds(1) || options.ScanInterval > HostTokenPolicy.RefreshInterval)
        {
            errors.Add($"Proof:ScanInterval must be between 00:00:01 and {HostTokenPolicy.RefreshInterval}.");
        }

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
