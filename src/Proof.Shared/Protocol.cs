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

/// <summary>RFC 8693 token exchange identifiers.</summary>
public static class TokenExchange
{
    public const string GrantType = "urn:ietf:params:oauth:grant-type:token-exchange";
    public const string JwtTokenType = "urn:ietf:params:oauth:token-type:jwt";

    /// <summary>RFC 8693 section 2.2.1: the issued token is not an OAuth access token.</summary>
    public const string NotApplicableTokenType = "N_A";
}
