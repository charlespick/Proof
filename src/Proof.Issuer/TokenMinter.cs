using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Proof.Shared;

namespace Proof.Issuer;

/// <summary>Mints the audience-specific JWT described in Design.md 6.4.</summary>
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
            [ProofClaimNames.Host] = identity.Host,
        };

        if (identity.VmName is not null)
        {
            claims[ProofClaimNames.VmName] = identity.VmName;
        }

        if (identity.Cluster is not null)
        {
            claims[ProofClaimNames.Cluster] = identity.Cluster;
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
