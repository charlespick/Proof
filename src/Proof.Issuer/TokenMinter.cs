using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Proof.Shared;

namespace Proof.Issuer;

/// <summary>
/// Mints the audience-specific JWT. The tenant, assigned ID and VM ID are claims of their own as well as parts of
/// <c>sub</c>, so consumers that map claims never need to parse the subject.
/// </summary>
public sealed class TokenMinter(SigningKeys keys, IOptions<IssuerOptions> options, TimeProvider time)
{
    private readonly JsonWebTokenHandler handler = new() { SetDefaultTimesOnTokenCreation = false };

    public TimeSpan Lifetime => options.Value.IssuedTokenLifetime;

    public string Mint(HostIdentity identity, string audience)
    {
        var now = time.GetUtcNow();
        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Sub] = identity.Subject,
            [JwtRegisteredClaimNames.Jti] = ProofTokenIds.NewJti(),
            [ProofClaimNames.Tenant] = identity.Identity.Tenant,
            [ProofClaimNames.AssignedId] = identity.Identity.AssignedId,
            [ProofClaimNames.VmId] = identity.VmId,
            [ProofClaimNames.SecurityTags] = identity.Identity.SecurityTags.ToArray(),
            [ProofClaimNames.Host] = identity.Host,
        };

        if (identity.VmName is not null)
        {
            claims[ProofClaimNames.VmName] = identity.VmName;
        }

        return handler.CreateToken(new SecurityTokenDescriptor
        {
            TokenType = ProofTokenTypes.IssuedToken,
            Issuer = options.Value.IssuerUrl,
            Audience = audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = (now + Lifetime).UtcDateTime,
            Claims = claims,
            SigningCredentials = keys.Credentials,
        });
    }
}
