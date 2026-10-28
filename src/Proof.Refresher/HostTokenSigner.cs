using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Proof.Shared;

namespace Proof.Refresher;

/// <summary>A running VM on this host.</summary>
/// <param name="Id">The VM ID as a lowercase hyphenated GUID.</param>
/// <param name="Name">The VM name now. Mutable and informational.</param>
public sealed record VirtualMachine(string Id, string Name);

/// <summary>A signed host token and whether <c>vm_name</c> had to be left out to fit in one KVP value.</summary>
public sealed record SignedHostToken(string Token, string Jti, DateTimeOffset Expires, bool VmNameOmitted);

/// <summary>Signs host tokens (Design.md 6.1) with the host key. Microsoft.IdentityModel builds and signs the JWS.</summary>
public sealed class HostTokenSigner
{
    private readonly JsonWebTokenHandler handler = new() { SetDefaultTimesOnTokenCreation = false };
    private readonly SigningCredentials credentials;
    private readonly RefresherOptions options;

    public HostTokenSigner(ECDsa hostKey, IOptions<RefresherOptions> options)
    {
        this.options = options.Value;
        Jwk = ProofKeys.CreatePublicJwk(hostKey);
        credentials = new SigningCredentials(new ECDsaSecurityKey(hostKey) { KeyId = Jwk.Kid }, ProofAlgorithms.Signing);

        // Fail at startup, not per VM, if the fixed claims alone cannot fit in a KVP value.
        var probe = Create(new VirtualMachine(Guid.Empty.ToString("D"), ""), DateTimeOffset.UnixEpoch, includeVmName: false);
        if (probe.Length > KvpLimits.MaxValueLength)
        {
            throw new InvalidOperationException(
                $"A host token without vm_name is {probe.Length} characters, over the {KvpLimits.MaxValueLength}-character KVP limit. Shorten Proof:IssuerUrl, Proof:HostId or Proof:Cluster.");
        }
    }

    /// <summary>The public host key, with <c>kid</c> set to its RFC 7638 thumbprint.</summary>
    public JsonWebKey Jwk { get; }

    public string Kid => Jwk.Kid;

    /// <summary>
    /// Signs a token for <paramref name="vm"/>. If it would not fit in one KVP value, <c>vm_name</c> is left out:
    /// it is informational, and one value keeps the guest side simple (no chunked keys).
    /// </summary>
    public SignedHostToken Sign(VirtualMachine vm, DateTimeOffset now)
    {
        var token = Create(vm, now, includeVmName: vm.Name.Length > 0);
        var omitted = false;
        if (token.Length > KvpLimits.MaxValueLength)
        {
            token = Create(vm, now, includeVmName: false);
            omitted = vm.Name.Length > 0;
        }

        var jti = new JsonWebToken(token).Id;
        return new SignedHostToken(token, jti, now + HostTokenPolicy.Lifetime, omitted);
    }

    private string Create(VirtualMachine vm, DateTimeOffset now, bool includeVmName)
    {
        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Sub] = vm.Id,
            [JwtRegisteredClaimNames.Jti] = ProofTokenIds.NewJti(),
        };

        if (includeVmName)
        {
            claims[ProofClaimNames.VmName] = vm.Name;
        }

        if (options.Cluster is not null)
        {
            claims[ProofClaimNames.Cluster] = options.Cluster;
        }

        return handler.CreateToken(new SecurityTokenDescriptor
        {
            TokenType = ProofTokenTypes.HostToken,
            Issuer = options.HostId,
            Audience = options.IssuerUrl,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = (now + HostTokenPolicy.Lifetime).UtcDateTime,
            Claims = claims,
            SigningCredentials = credentials,
        });
    }
}
