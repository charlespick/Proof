using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Proof.Shared;

namespace Proof.Issuer;

/// <summary>
/// The issuer's signing key and the public keys it publishes. Loaded once at startup from the mounted Secret;
/// a rotation is delivered by GitOps and takes effect when the pods roll.
/// </summary>
public sealed class SigningKeys
{
    public SigningKeys(IOptions<IssuerOptions> options)
    {
        var o = options.Value;

        var signingKey = LoadKey(o.SigningKeyPath, requirePrivate: true);
        var signingJwk = ProofKeys.CreatePublicJwk(signingKey);
        Credentials = new SigningCredentials(
            new ECDsaSecurityKey(signingKey) { KeyId = signingJwk.Kid },
            ProofAlgorithms.Signing);

        var published = new List<JsonWebKey> { signingJwk };
        foreach (var path in o.AdditionalPublicKeyPaths)
        {
            using var key = LoadKey(path, requirePrivate: false);
            var jwk = ProofKeys.CreatePublicJwk(key);
            if (published.Any(k => k.Kid == jwk.Kid))
            {
                throw new InvalidOperationException($"Public key {path} is already published.");
            }
            published.Add(jwk);
        }

        PublishedKeys = published;
    }

    public SigningCredentials Credentials { get; }

    /// <summary>The signing key first, then any additional public keys. Public parameters only.</summary>
    public IReadOnlyList<JsonWebKey> PublishedKeys { get; }

    private static ECDsa LoadKey(string path, bool requirePrivate)
    {
        var key = ECDsa.Create();
        try
        {
            key.ImportFromPem(File.ReadAllText(path));
            if (!ProofKeys.IsP256(key))
            {
                throw new InvalidOperationException($"Key {path} is not ECDSA P-256.");
            }

            if (requirePrivate)
            {
                // A public-only PEM imports cleanly but cannot sign; find out now rather than on the first request.
                key.SignData([0], HashAlgorithmName.SHA256);
            }

            return key;
        }
        catch (CryptographicException ex)
        {
            key.Dispose();
            throw new InvalidOperationException($"Key {path} could not be loaded as an ECDSA {(requirePrivate ? "private" : "public")} key.", ex);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }
}
