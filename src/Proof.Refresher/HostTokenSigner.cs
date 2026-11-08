using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Proof.Shared;

namespace Proof.Refresher;

/// <summary>A signed host token and whether <c>vm_name</c> had to be left out to fit in one KVP value.</summary>
public sealed record SignedHostToken(string Token, string Jti, DateTimeOffset Expires, bool VmNameOmitted)
{
    /// <summary>False if the token is too long for one KVP value even without <c>vm_name</c>. It must not be written.</summary>
    public bool Fits => Token.Length <= KvpLimits.MaxValueLength;
}

/// <summary>Signs host tokens with the host key. Microsoft.IdentityModel builds and signs the JWS.</summary>
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

        // Fail at startup, not per VM, if the fixed claims and the least identity cannot fit in a KVP value.
        VmIdentity.TryCreate("a", "a", [], out var least, out _);
        var probe = Create(new VirtualMachine(Guid.Empty.ToString("D"), "", null), least!, DateTimeOffset.UnixEpoch, includeVmName: false);
        if (probe.Length > KvpLimits.MaxValueLength)
        {
            throw new InvalidOperationException(
                $"A host token without vm_name is {probe.Length} characters before any identity, over the {KvpLimits.MaxValueLength}-character KVP limit. Shorten Proof:IssuerUrl or Proof:HostId.");
        }
    }

    /// <summary>The public host key, with <c>kid</c> set to its RFC 7638 thumbprint.</summary>
    public JsonWebKey Jwk { get; }

    public string Kid => Jwk.Kid;

    /// <summary>
    /// Signs a token for <paramref name="vm"/> with <paramref name="identity"/>. If it would not fit in one KVP value,
    /// <c>vm_name</c> is left out: it is informational, and one value keeps the guest side simple (no chunked keys).
    /// The identity is never shortened, so the result may still not <see cref="SignedHostToken.Fits"/>.
    /// </summary>
    public SignedHostToken Sign(VirtualMachine vm, VmIdentity identity, DateTimeOffset now)
    {
        var token = Create(vm, identity, now, includeVmName: vm.Name.Length > 0);
        var omitted = false;
        if (token.Length > KvpLimits.MaxValueLength && vm.Name.Length > 0)
        {
            token = Create(vm, identity, now, includeVmName: false);
            omitted = true;
        }

        var jti = new JsonWebToken(token).Id;
        return new SignedHostToken(token, jti, now + HostTokenPolicy.Lifetime, omitted);
    }

    private string Create(VirtualMachine vm, VmIdentity identity, DateTimeOffset now, bool includeVmName)
    {
        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Sub] = vm.Id,
            [JwtRegisteredClaimNames.Jti] = ProofTokenIds.NewJti(),
            [ProofClaimNames.Tenant] = identity.Tenant,
            [ProofClaimNames.AssignedId] = identity.AssignedId,
            [ProofClaimNames.SecurityTags] = identity.SecurityTags.ToArray(),
        };

        if (includeVmName)
        {
            claims[ProofClaimNames.VmName] = vm.Name;
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
