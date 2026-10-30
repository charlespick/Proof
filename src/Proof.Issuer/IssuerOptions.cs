using System.Net;
using System.Net.Sockets;
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

    /// <summary><c>/token</c> requests allowed per source address per minute.</summary>
    public int TokenRequestsPerMinute { get; set; } = 60;

    /// <summary>
    /// Addresses or CIDR networks of the proxies in front of the issuer, such as the ingress pods. Only a connection
    /// from one of these may set the source address with <c>X-Forwarded-For</c>, and only the rightmost entry is
    /// taken, the one that proxy added. Empty means the connection's own address is the source.
    /// </summary>
    public List<string> TrustedProxies { get; set; } = [];

    /// <summary>A <see cref="TrustedProxies"/> entry: a CIDR network, or a single address.</summary>
    public static bool TryParseNetwork(string? value, out IPNetwork network)
    {
        network = default;
        if (value is null)
        {
            return false;
        }

        if (IPAddress.TryParse(value, out var address) && !value.Contains('/'))
        {
            network = new IPNetwork(address, address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);
            return true;
        }

        // .NET masks host bits away, so 10.0.0.5/8 would quietly trust all of 10/8. Refuse it instead.
        return IPNetwork.TryParse(value, out network)
            && IPAddress.TryParse(value.AsSpan(0, value.IndexOf('/')), out var written)
            && written.Equals(network.BaseAddress);
    }
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

        if (options.TrustedProxies.FirstOrDefault(p => !IssuerOptions.TryParseNetwork(p, out _)) is { } bad)
        {
            errors.Add($"Proof:TrustedProxies entry '{bad}' is not an IP address or a CIDR network such as 10.1.0.0/16.");
        }

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
