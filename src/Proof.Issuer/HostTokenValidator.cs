using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Proof.Issuer.Allowlist;
using Proof.Shared;

namespace Proof.Issuer;

/// <summary>Who a verified host token says the VM is.</summary>
/// <param name="Subject">The identity: the VM ID scoped by the signing host's cluster or host, from the allowlist (<see cref="ProofSubjects"/>).</param>
/// <param name="VmId">The VM ID, a lowercase hyphenated GUID. Unique only within its cluster or host.</param>
/// <param name="Host">The allowlisted host that signed the token.</param>
/// <param name="Kid">The host key that signed the token.</param>
/// <param name="Jti">The host token's <c>jti</c>, for logs.</param>
/// <param name="VmName">Host-asserted and informational.</param>
/// <param name="Cluster">The signing host's cluster on the allowlist, which the host token's <c>cluster</c> matched.</param>
public sealed record HostIdentity(string Subject, string VmId, string Host, string Kid, string Jti, string? VmName, string? Cluster);

/// <summary>Why a host token was refused. Logged, never returned to the caller.</summary>
public enum HostTokenFailure
{
    None,
    AllowlistNotLoaded,
    TooLarge,
    Malformed,
    Encrypted,
    DisallowedAlgorithm,
    WrongType,
    UnknownKey,
    ValidationFailed,
    InvalidClaim,
    IssuedInFuture,
    LifetimeTooLong,
    InvalidSubject,
    ClusterMismatch,
}

/// <param name="Detail">Extra context for logs, such as the library exception type. Never token content.</param>
/// <param name="Kid">The signing key, once it has been matched to the allowlist.</param>
public sealed record HostTokenResult(HostIdentity? Identity, HostTokenFailure Failure, string? Detail = null, string? Kid = null)
{
    public bool IsValid => Identity is not null;
}

/// <summary>
/// Checks a host token in the order Design.md 6.3 sets out. Microsoft.IdentityModel does the signature,
/// issuer, audience, type, algorithm and expiry checks; this class adds the policy the library has no setting for.
/// </summary>
/// <remarks>
/// Microsoft.IdentityModel checks <c>nbf</c> and <c>exp</c> against the system clock (its TimeProvider hook is not public),
/// so the checks here read the system clock too and the two can never disagree.
/// </remarks>
public sealed class HostTokenValidator(AllowlistMonitor allowlist, IOptions<IssuerOptions> options)
{
    private readonly JsonWebTokenHandler handler = new()
    {
        MaximumTokenSizeInBytes = HostTokenPolicy.MaxEncodedLength,
        MapInboundClaims = false,
    };

    public async Task<HostTokenResult> ValidateAsync(string token)
    {
        // 1. Size, before any parsing.
        if (token.Length > HostTokenPolicy.MaxEncodedLength)
        {
            return Fail(HostTokenFailure.TooLarge);
        }

        var list = allowlist.Current;
        if (list is null)
        {
            return Fail(HostTokenFailure.AllowlistNotLoaded);
        }

        // 2. Header. Read without validating only to pick the allowlisted key; the header never chooses the algorithm.
        JsonWebToken unverified;
        try
        {
            unverified = handler.ReadJsonWebToken(token);
        }
        catch (Exception ex)
        {
            return Fail(HostTokenFailure.Malformed, ex.GetType().Name);
        }

        if (unverified.IsEncrypted)
        {
            return Fail(HostTokenFailure.Encrypted);
        }

        if (!string.Equals(unverified.Alg, ProofAlgorithms.Signing, StringComparison.Ordinal))
        {
            return Fail(HostTokenFailure.DisallowedAlgorithm);
        }

        if (!string.Equals(unverified.Typ, ProofTokenTypes.HostToken, StringComparison.Ordinal))
        {
            return Fail(HostTokenFailure.WrongType);
        }

        var now = DateTimeOffset.UtcNow;
        if (!list.TryGetUsableKey(unverified.Kid, now, out var hostKey))
        {
            return Fail(HostTokenFailure.UnknownKey);
        }

        // 3 to 5. Signature with that one key, iss for that kid, aud, typ, alg, nbf and exp with skew.
        var parameters = new TokenValidationParameters
        {
            ValidAlgorithms = [ProofAlgorithms.Signing],
            ValidTypes = [ProofTokenTypes.HostToken],
            IssuerSigningKey = hostKey.Key,
            TryAllIssuerSigningKeys = false,
            ValidIssuer = hostKey.Host,
            ValidAudience = options.Value.IssuerUrl,
            IgnoreTrailingSlashWhenValidatingAudience = false,
            RequireAudience = true,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ValidateLifetime = true,
            ClockSkew = HostTokenPolicy.ClockSkew,
        };

        var result = await handler.ValidateTokenAsync(token, parameters);
        if (!result.IsValid)
        {
            return Fail(HostTokenFailure.ValidationFailed, result.Exception?.GetType().Name, hostKey.Kid);
        }

        var jwt = (JsonWebToken)result.SecurityToken;

        // 5 and 6. What the library has no setting for: one audience, every required claim, iat, and the lifetime cap.
        if (jwt.Audiences.Count() != 1
            || !jwt.TryGetPayloadValue<long>(JwtRegisteredClaimNames.Iat, out var iat)
            || !jwt.TryGetPayloadValue<long>(JwtRegisteredClaimNames.Nbf, out _)
            || !jwt.TryGetPayloadValue<long>(JwtRegisteredClaimNames.Exp, out var exp)
            || string.IsNullOrEmpty(jwt.Id)
            || !TryGetOptionalString(jwt, ProofClaimNames.VmName, out var vmName)
            || !TryGetOptionalString(jwt, ProofClaimNames.Cluster, out var cluster))
        {
            return Fail(HostTokenFailure.InvalidClaim, kid: hostKey.Kid);
        }

        if (DateTimeOffset.FromUnixTimeSeconds(iat) > now + HostTokenPolicy.ClockSkew)
        {
            return Fail(HostTokenFailure.IssuedInFuture, kid: hostKey.Kid);
        }

        if (exp - iat > (long)HostTokenPolicy.MaxLifetime.TotalSeconds)
        {
            return Fail(HostTokenFailure.LifetimeTooLong, kid: hostKey.Kid);
        }

        if (!IsCanonicalVmId(jwt.Subject))
        {
            return Fail(HostTokenFailure.InvalidSubject, kid: hostKey.Kid);
        }

        // 7. The host's cluster, or its absence, as the allowlist records it. The subject is scoped by the allowlist
        // entry alone; a host token that disagrees with it comes from a misconfigured host.
        if (!string.Equals(cluster, hostKey.Cluster, StringComparison.Ordinal))
        {
            return Fail(HostTokenFailure.ClusterMismatch, kid: hostKey.Kid);
        }

        return new HostTokenResult(
            new HostIdentity(ProofSubjects.For(hostKey.Host, hostKey.Cluster, jwt.Subject), jwt.Subject, hostKey.Host, hostKey.Kid, jwt.Id, vmName, hostKey.Cluster),
            HostTokenFailure.None,
            Kid: hostKey.Kid);
    }

    /// <summary>A VM ID in the one form Proof uses: a lowercase, hyphenated GUID.</summary>
    public static bool IsCanonicalVmId(string? value) =>
        Guid.TryParseExact(value, "D", out var id) && string.Equals(id.ToString("D"), value, StringComparison.Ordinal);

    /// <summary>False if the claim is present but not a string; true with null if it is absent.</summary>
    private static bool TryGetOptionalString(JsonWebToken jwt, string name, out string? value)
    {
        value = null;
        if (!jwt.TryGetClaim(name, out var claim))
        {
            return true;
        }

        if (claim.ValueType != ClaimValueTypes.String || string.IsNullOrEmpty(claim.Value))
        {
            return false;
        }

        value = claim.Value;
        return true;
    }

    private static HostTokenResult Fail(HostTokenFailure failure, string? detail = null, string? kid = null) =>
        new(null, failure, detail, kid);
}
