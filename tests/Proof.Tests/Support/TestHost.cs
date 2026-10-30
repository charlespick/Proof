using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Proof.Shared;

namespace Proof.Tests.Support;

/// <summary>A fake Hyper-V host: a P-256 key, its allowlist entry, and host tokens signed the way the refresher will sign them.</summary>
public sealed class TestHost
{
    public const string IssuerUrl = "https://proof.test";
    public const string VmId = "11111111-2222-3333-4444-555555555555";

    public TestHost(string hostId = "hv-host-01", string? cluster = "prod")
    {
        HostId = hostId;
        Cluster = cluster;
        Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Jwk = ProofKeys.CreatePublicJwk(Key);
    }

    public string HostId { get; }
    public string? Cluster { get; }
    public ECDsa Key { get; }
    public JsonWebKey Jwk { get; }
    public string Kid => Jwk.Kid;

    /// <summary>The <c>sub</c> the issuer gives this host's VM: scoped by its cluster, or by the host when it has none.</summary>
    public string Subject => Cluster is null ? $"host:{HostId}/{VmId}" : $"cluster:{Cluster}/{VmId}";

    /// <summary>This host's allowlist entry as YAML, indented to sit under <c>hosts:</c>.</summary>
    public string AllowlistEntry(string status = "active", string? notAfter = null, string? clusterOverride = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"  - host: {HostId}");
        var cluster = clusterOverride ?? Cluster;
        if (cluster is not null)
        {
            sb.AppendLine($"    cluster: {cluster}");
        }
        sb.AppendLine("    keys:");
        sb.AppendLine($"      - kid: {Kid}");
        sb.AppendLine($"        status: {status}");
        if (notAfter is not null)
        {
            sb.AppendLine($"        not_after: {notAfter}");
        }
        sb.AppendLine($"        jwk: {{ kty: EC, crv: P-256, x: {Jwk.X}, y: {Jwk.Y} }}");
        return sb.ToString();
    }

    public static string Allowlist(params string[] entries) => "version: 1\nhosts:\n" + string.Concat(entries);

    /// <summary>The claims a well-formed host token carries, relative to now. Tests edit them to break one rule at a time.</summary>
    public Dictionary<string, object> DefaultClaims(DateTimeOffset? now = null)
    {
        var t = (now ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Iss] = HostId,
            [JwtRegisteredClaimNames.Aud] = IssuerUrl,
            [JwtRegisteredClaimNames.Sub] = VmId,
            [ProofClaimNames.VmName] = "web01",
            [JwtRegisteredClaimNames.Iat] = t,
            [JwtRegisteredClaimNames.Nbf] = t,
            [JwtRegisteredClaimNames.Exp] = t + (long)HostTokenPolicy.Lifetime.TotalSeconds,
            [JwtRegisteredClaimNames.Jti] = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)),
        };
        if (Cluster is not null)
        {
            claims[ProofClaimNames.Cluster] = Cluster;
        }
        return claims;
    }

    public string CreateToken(Action<Dictionary<string, object>>? edit = null, string typ = ProofTokenTypes.HostToken, ECDsa? signWith = null, string? kid = null)
    {
        var claims = DefaultClaims();
        edit?.Invoke(claims);
        var credentials = new SigningCredentials(
            new ECDsaSecurityKey(signWith ?? Key) { KeyId = kid ?? Kid },
            ProofAlgorithms.Signing);
        return Sign(claims, credentials, typ);
    }

    public static string Sign(Dictionary<string, object> claims, SigningCredentials credentials, string typ)
    {
        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        return handler.CreateToken(new SecurityTokenDescriptor
        {
            TokenType = typ,
            Claims = claims,
            SigningCredentials = credentials,
        });
    }
}
