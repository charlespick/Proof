using Microsoft.Extensions.Options;
using Proof.Shared;

namespace Proof.Issuer;

/// <summary>The OIDC discovery document and JWKS (Design.md 6.5).</summary>
public static class DiscoveryEndpoints
{
    public const string DiscoveryPath = "/.well-known/openid-configuration";
    public const string JwksPath = "/.well-known/jwks.json";

    /// <summary>Short, so a rotation reaches verifiers quickly (Design.md 7.3).</summary>
    private const string CacheControl = "public, max-age=300";

    public static IEndpointRouteBuilder MapDiscovery(this IEndpointRouteBuilder app)
    {
        app.MapGet(DiscoveryPath, (HttpContext http, IOptions<IssuerOptions> options) =>
        {
            var issuer = options.Value.IssuerUrl;
            http.Response.Headers.CacheControl = CacheControl;
            return Results.Json(
                new DiscoveryDocument(
                    Issuer: issuer,
                    JwksUri: issuer + JwksPath,
                    TokenEndpoint: issuer + Issuer.TokenEndpoint.Path,
                    ResponseTypesSupported: ["id_token"],
                    SubjectTypesSupported: ["public"],
                    IdTokenSigningAlgValuesSupported: [ProofAlgorithms.Signing],
                    GrantTypesSupported: [TokenExchange.GrantType]),
                Issuer.TokenEndpoint.Json);
        });

        app.MapGet(JwksPath, (HttpContext http, SigningKeys keys) =>
        {
            http.Response.Headers.CacheControl = CacheControl;
            return Results.Json(
                new JwksDocument(keys.PublishedKeys
                    .Select(k => new Jwk(k.Kty, k.Crv, k.X, k.Y, k.Kid, "sig", ProofAlgorithms.Signing))
                    .ToArray()),
                Issuer.TokenEndpoint.Json);
        });

        return app;
    }

    private sealed record DiscoveryDocument(
        string Issuer,
        string JwksUri,
        string TokenEndpoint,
        string[] ResponseTypesSupported,
        string[] SubjectTypesSupported,
        string[] IdTokenSigningAlgValuesSupported,
        string[] GrantTypesSupported);

    private sealed record JwksDocument(Jwk[] Keys);

    private sealed record Jwk(string Kty, string Crv, string X, string Y, string Kid, string Use, string Alg);
}
