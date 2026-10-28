using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Proof.Shared;

/// <summary>Key helpers shared by the refresher and the issuer. Encoding and thumbprints come from Microsoft.IdentityModel.</summary>
public static class ProofKeys
{
    private const string P256Oid = "1.2.840.10045.3.1.7";

    /// <summary>True if <paramref name="key"/> is on the P-256 curve that ES256 requires.</summary>
    public static bool IsP256(ECDsa key)
    {
        var curve = key.ExportParameters(includePrivateParameters: false).Curve;
        return curve.IsNamed
            && (curve.Oid.Value == P256Oid
                || curve.Oid.FriendlyName is "nistP256" or "ECDSA_P256" or "secp256r1" or "prime256v1");
    }

    /// <summary>
    /// The public half of <paramref name="key"/> as a JWK with <c>kid</c> set to its RFC 7638 thumbprint.
    /// Only public parameters are exported, so this works for non-exportable CNG and TPM keys.
    /// </summary>
    public static JsonWebKey CreatePublicJwk(ECDsa key)
    {
        if (!IsP256(key))
        {
            throw new ArgumentException("Proof keys must be ECDSA P-256.", nameof(key));
        }

        var q = key.ExportParameters(includePrivateParameters: false).Q;
        var jwk = new JsonWebKey
        {
            Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve,
            Crv = JsonWebKeyECTypes.P256,
            X = Base64UrlEncoder.Encode(q.X),
            Y = Base64UrlEncoder.Encode(q.Y),
        };
        jwk.Kid = ComputeKid(jwk);
        return jwk;
    }

    /// <summary>The RFC 7638 JWK thumbprint of <paramref name="jwk"/>, base64url encoded. Proof uses it as <c>kid</c>.</summary>
    public static string ComputeKid(JsonWebKey jwk) => Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());
}
