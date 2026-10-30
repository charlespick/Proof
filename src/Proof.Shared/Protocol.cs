using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.Tokens;

namespace Proof.Shared;

/// <summary>Claim names Proof adds to the registered JWT claims.</summary>
public static class ProofClaimNames
{
    /// <summary>VM name at signing time. Host-asserted and informational.</summary>
    public const string VmName = "vm_name";

    /// <summary>Cluster name. Host-asserted; optionally scoped against the allowlist.</summary>
    public const string Cluster = "cluster";

    /// <summary>Host ID that signed the host token, copied into issued JWTs. Informational.</summary>
    public const string Host = "host";
}

/// <summary>JOSE <c>typ</c> header values. They differ so one token type can never pass as the other.</summary>
public static class ProofTokenTypes
{
    public const string HostToken = "proof-host+jwt";
    public const string IssuedToken = "JWT";
}

public static class ProofAlgorithms
{
    /// <summary>The only algorithm Proof signs with or accepts (ES256).</summary>
    public const string Signing = SecurityAlgorithms.EcdsaSha256;
}

/// <summary>Validation settings shared by the refresher (which signs host tokens) and the issuer (which checks them).</summary>
public static class HostTokenPolicy
{
    /// <summary><c>exp</c> minus <c>iat</c> for host tokens the refresher signs.</summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(20);

    /// <summary>How often the refresher rewrites each VM's token.</summary>
    public static readonly TimeSpan RefreshInterval = TimeSpan.FromMinutes(5);

    /// <summary>The longest <c>exp</c> minus <c>iat</c> the issuer accepts.</summary>
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromMinutes(30);

    /// <summary>Host tokens longer than this are refused before parsing.</summary>
    public const int MaxEncodedLength = 4096;

    /// <summary>Clock skew allowed on every <c>nbf</c>, <c>exp</c> and <c>iat</c> check.</summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(2);
}

/// <summary>KVP key names in the VM's External pool.</summary>
public static class KvpKeys
{
    public const string Token = "proof.v1.token";
}

/// <summary>KVP size limits, measured on a Windows Server 2025 Hyper-V host.</summary>
public static class KvpLimits
{
    /// <summary>
    /// The longest value the host accepts, in UTF-16 characters: 2048 bytes including the terminator.
    /// <c>ModifyKvpItems</c> takes 1023 characters and refuses 1024 with error 32773.
    /// </summary>
    public const int MaxValueLength = 1023;
}

public static class ProofIssuerUrl
{
    /// <summary>
    /// True for an issuer URL Proof accepts: absolute https with no trailing slash, query, fragment or user info.
    /// It is the <c>iss</c> of issued JWTs and the <c>aud</c> of host tokens, so the refresher and issuer share one rule.
    /// </summary>
    public static bool IsValid([NotNullWhen(true)] string? value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var url)
        && url.Scheme == Uri.UriSchemeHttps
        && !value.EndsWith('/')
        && string.IsNullOrEmpty(url.Query)
        && string.IsNullOrEmpty(url.Fragment)
        && string.IsNullOrEmpty(url.UserInfo);
}

/// <summary>
/// Host and cluster names, as the refresher is configured and the allowlist lists them: letters, digits, dot, hyphen
/// and underscore, so they paste into YAML as they are and never contain the <c>/</c> or <c>:</c> of a subject.
/// </summary>
public static partial class ProofNames
{
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")]
    private static partial Regex Pattern();

    public static bool IsValid([NotNullWhen(true)] string? name) => name is not null && Pattern().IsMatch(name);
}

/// <summary>
/// The <c>sub</c> of issued JWTs. Hyper-V keeps VM IDs unique within a failover cluster, or within a standalone host,
/// but not across them: an import or a restore keeps the ID it had. So the VM ID is scoped by the cluster, or by the
/// host when it is in no cluster, as the issuer's allowlist records it. The host token's own claims never choose it.
/// </summary>
public static class ProofSubjects
{
    public const string ClusterPrefix = "cluster:";
    public const string HostPrefix = "host:";

    /// <summary><c>cluster:&lt;cluster&gt;/&lt;vmid&gt;</c>, or <c>host:&lt;host&gt;/&lt;vmid&gt;</c> for a host in no cluster.</summary>
    public static string For(string host, string? cluster, string vmId) =>
        cluster is not null ? $"{ClusterPrefix}{cluster}/{vmId}" : $"{HostPrefix}{host}/{vmId}";
}

public static class ProofTokenIds
{
    /// <summary>A random 128-bit <c>jti</c>, as lowercase hex.</summary>
    public static string NewJti() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
}

/// <summary>RFC 8693 token exchange identifiers.</summary>
public static class TokenExchange
{
    public const string GrantType = "urn:ietf:params:oauth:grant-type:token-exchange";
    public const string JwtTokenType = "urn:ietf:params:oauth:token-type:jwt";

    /// <summary>RFC 8693 section 2.2.1: the issued token is not an OAuth access token.</summary>
    public const string NotApplicableTokenType = "N_A";

    /// <summary>The path of the token endpoint under the issuer URL.</summary>
    public const string EndpointPath = "/token";

    public const int MaxAudienceLength = 256;

    /// <summary>An audience the issuer will consider: 1 to 256 characters, no whitespace or control characters.</summary>
    public static bool IsWellFormedAudience([NotNullWhen(true)] string? audience) =>
        !string.IsNullOrEmpty(audience)
        && audience.Length <= MaxAudienceLength
        && !audience.Any(c => char.IsWhiteSpace(c) || char.IsControl(c));
}
