using Microsoft.Extensions.Options;
using Proof.Shared;

namespace Proof.Issuer;

/// <summary>Issuer configuration, bound from the <c>Proof</c> section.</summary>
public sealed class IssuerOptions
{
    public const string SectionName = "Proof";

    /// <summary>The longest issued-token lifetime the design allows (Design.md 6.4).</summary>
    public static readonly TimeSpan MaxIssuedTokenLifetime = TimeSpan.FromMinutes(10);

    /// <summary>
    /// The issuer URL: https, no trailing slash. It is the <c>iss</c> of issued JWTs and the <c>aud</c> host tokens must carry.
    /// </summary>
    public string IssuerUrl { get; set; } = "";

    /// <summary>Path to the host allowlist YAML file, inside a ConfigMap mounted as a directory.</summary>
    public string AllowlistPath { get; set; } = "";

    /// <summary>How often the allowlist file is checked for changes.</summary>
    public TimeSpan AllowlistPollInterval { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Path to the PEM-encoded ES256 private key that signs issued JWTs.</summary>
    public string SigningKeyPath { get; set; } = "";

    /// <summary>
    /// PEM-encoded public keys published in the JWKS alongside the signing key, for rotation:
    /// the next key before it signs, or the previous key until its last token has expired.
    /// </summary>
    public List<string> AdditionalPublicKeyPaths { get; set; } = [];

    public TimeSpan IssuedTokenLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>If non-empty, only these audiences may be requested. Empty means any audience.</summary>
    public List<string> AllowedAudiences { get; set; } = [];

    /// <summary>If true, a host token's <c>cluster</c> must equal the cluster on its host's allowlist entry.</summary>
    public bool EnforceClusterScope { get; set; }

    /// <summary><c>/token</c> requests allowed per source address per minute.</summary>
    public int TokenRequestsPerMinute { get; set; } = 60;
}

public sealed class IssuerOptionsValidator : IValidateOptions<IssuerOptions>
{
    public ValidateOptionsResult Validate(string? name, IssuerOptions options)
    {
        var errors = new List<string>();

        if (!ProofIssuerUrl.IsValid(options.IssuerUrl))
        {
            errors.Add("Proof:IssuerUrl must be an absolute https URL with no trailing slash, query or fragment.");
        }

        if (string.IsNullOrWhiteSpace(options.AllowlistPath))
        {
            errors.Add("Proof:AllowlistPath is required.");
        }

        if (string.IsNullOrWhiteSpace(options.SigningKeyPath))
        {
            errors.Add("Proof:SigningKeyPath is required.");
        }

        if (options.AllowlistPollInterval <= TimeSpan.Zero)
        {
            errors.Add("Proof:AllowlistPollInterval must be positive.");
        }

        if (options.IssuedTokenLifetime <= TimeSpan.Zero || options.IssuedTokenLifetime > IssuerOptions.MaxIssuedTokenLifetime)
        {
            errors.Add($"Proof:IssuedTokenLifetime must be positive and at most {IssuerOptions.MaxIssuedTokenLifetime}.");
        }

        if (options.AllowedAudiences.Any(a => !TokenExchange.IsWellFormedAudience(a)))
        {
            errors.Add("Proof:AllowedAudiences contains an empty or malformed audience.");
        }

        if (options.TokenRequestsPerMinute <= 0)
        {
            errors.Add("Proof:TokenRequestsPerMinute must be positive.");
        }

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
