using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Proof.Issuer;
using Proof.Shared;
using Proof.Tests.Support;

namespace Proof.Tests;

/// <summary>The issuer over HTTP: token exchange, discovery, JWKS, health and limits.</summary>
public sealed class IssuerEndpointTests : IDisposable
{
    private readonly TestHost host = new();
    private readonly IssuerApp app;
    private readonly HttpClient client;

    public IssuerEndpointTests()
    {
        app = new IssuerApp(TestHost.Allowlist(host.AllowlistEntry()));
        client = app.CreateClient();
    }

    public void Dispose()
    {
        client.Dispose();
        app.Dispose();
    }

    private static Dictionary<string, string> ExchangeForm(string subjectToken, string? audience = "my-service")
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchange.GrantType,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = TokenExchange.JwtTokenType,
            ["requested_token_type"] = TokenExchange.JwtTokenType,
        };
        if (audience is not null)
        {
            form["audience"] = audience;
        }
        return form;
    }

    private Task<HttpResponseMessage> PostAsync(IEnumerable<KeyValuePair<string, string>> form, string path = TokenEndpoint.Path) =>
        client.PostAsync(path, new FormUrlEncodedContent(form), TestContext.Current.CancellationToken);

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).RootElement;

    private static async Task AssertErrorAsync(HttpResponseMessage response, string error)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await ReadJsonAsync(response);
        Assert.Equal(error, body.GetProperty("error").GetString());
        Assert.DoesNotContain("Host", body.GetProperty("error_description").GetString());
    }

    [Fact]
    public async Task ExchangesHostTokenForAudienceJwt()
    {
        var response = await PostAsync(ExchangeForm(host.CreateToken()));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        var body = await ReadJsonAsync(response);
        Assert.Equal(TokenExchange.JwtTokenType, body.GetProperty("issued_token_type").GetString());
        Assert.Equal("N_A", body.GetProperty("token_type").GetString());
        Assert.Equal(300, body.GetProperty("expires_in").GetInt32());

        var jwt = new JsonWebToken(body.GetProperty("access_token").GetString());
        Assert.Equal("ES256", jwt.Alg);
        Assert.Equal("JWT", jwt.Typ);
        Assert.Equal(ProofKeys.CreatePublicJwk(app.SigningKey).Kid, jwt.Kid);
        Assert.Equal(TestHost.IssuerUrl, jwt.Issuer);
        Assert.Equal("cluster:prod/" + TestHost.VmId, jwt.Subject);
        Assert.Equal("my-service", jwt.GetPayloadValue<string>("aud"));
        Assert.Equal(host.HostId, jwt.GetPayloadValue<string>("host"));
        Assert.Equal("web01", jwt.GetPayloadValue<string>("vm_name"));
        Assert.Equal("prod", jwt.GetPayloadValue<string>("cluster"));
        Assert.Equal(32, jwt.Id.Length);
        Assert.Equal(TimeSpan.FromMinutes(5), jwt.ValidTo - jwt.IssuedAt);
        Assert.Equal(jwt.IssuedAt, jwt.ValidFrom);
    }

    [Fact]
    public async Task ScopesTheSubjectByHostForAHostInNoCluster()
    {
        var standalone = new TestHost("hv-lab-07", cluster: null);
        using var standaloneApp = new IssuerApp(TestHost.Allowlist(standalone.AllowlistEntry()));
        using var standaloneClient = standaloneApp.CreateClient();
        var response = await standaloneClient.PostAsync(
            TokenEndpoint.Path, new FormUrlEncodedContent(ExchangeForm(standalone.CreateToken())), TestContext.Current.CancellationToken);

        var jwt = new JsonWebToken((await ReadJsonAsync(response)).GetProperty("access_token").GetString());
        Assert.Equal("host:hv-lab-07/" + TestHost.VmId, jwt.Subject);
        Assert.False(jwt.TryGetClaim("cluster", out _));
    }

    [Fact]
    public async Task IssuedJwtVerifiesAgainstPublishedJwksLikeAnyOidcToken()
    {
        var exchange = await ReadJsonAsync(await PostAsync(ExchangeForm(host.CreateToken())));
        var issued = exchange.GetProperty("access_token").GetString()!;

        // A consumer's view (Design.md 6.6): discovery, then the JWKS it names, then standard validation.
        var discovery = await ReadJsonAsync(await client.GetAsync(DiscoveryEndpoints.DiscoveryPath, TestContext.Current.CancellationToken));
        var jwksPath = new Uri(discovery.GetProperty("jwks_uri").GetString()!).AbsolutePath;
        var jwksJson = await client.GetStringAsync(jwksPath, TestContext.Current.CancellationToken);
        var jwks = new JsonWebKeySet(jwksJson);

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(issued, new TokenValidationParameters
        {
            ValidIssuer = TestHost.IssuerUrl,
            ValidAudience = "my-service",
            ValidAlgorithms = ["ES256"],
            IssuerSigningKeys = jwks.GetSigningKeys(),
            ClockSkew = TimeSpan.FromMinutes(2),
        });

        Assert.True(result.IsValid, result.Exception?.Message);
    }

    [Fact]
    public async Task HostTokenIsRefusedByAConsumer()
    {
        var jwks = new JsonWebKeySet(await client.GetStringAsync(DiscoveryEndpoints.JwksPath, TestContext.Current.CancellationToken));

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(host.CreateToken(), new TokenValidationParameters
        {
            ValidIssuer = TestHost.IssuerUrl,
            ValidAudience = "my-service",
            ValidAlgorithms = ["ES256"],
            IssuerSigningKeys = jwks.GetSigningKeys(),
        });

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task IssuedJwtIsRefusedAsAHostToken()
    {
        var exchange = await ReadJsonAsync(await PostAsync(ExchangeForm(host.CreateToken())));
        var issued = exchange.GetProperty("access_token").GetString()!;

        await AssertErrorAsync(await PostAsync(ExchangeForm(issued)), "invalid_request");
    }

    [Fact]
    public async Task DiscoveryDocumentHasRequiredMembers()
    {
        var response = await client.GetAsync(DiscoveryEndpoints.DiscoveryPath, TestContext.Current.CancellationToken);
        var doc = await ReadJsonAsync(response);

        Assert.Equal("public, max-age=300", response.Headers.CacheControl?.ToString());
        Assert.Equal(TestHost.IssuerUrl, doc.GetProperty("issuer").GetString());
        Assert.Equal(TestHost.IssuerUrl + "/.well-known/jwks.json", doc.GetProperty("jwks_uri").GetString());
        Assert.Equal(TestHost.IssuerUrl + "/token", doc.GetProperty("token_endpoint").GetString());
        Assert.Equal(["id_token"], doc.GetProperty("response_types_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(["public"], doc.GetProperty("subject_types_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(["ES256"], doc.GetProperty("id_token_signing_alg_values_supported").EnumerateArray().Select(e => e.GetString()));
    }

    [Fact]
    public async Task JwksPublishesPublicKeysWithKidUseAndAlg()
    {
        var response = await client.GetAsync(DiscoveryEndpoints.JwksPath, TestContext.Current.CancellationToken);
        var key = Assert.Single((await ReadJsonAsync(response)).GetProperty("keys").EnumerateArray());

        Assert.Equal("public, max-age=300", response.Headers.CacheControl?.ToString());
        Assert.Equal(
            ["kty", "crv", "x", "y", "kid", "use", "alg"],
            key.EnumerateObject().Select(p => p.Name));
        Assert.Equal("EC", key.GetProperty("kty").GetString());
        Assert.Equal("P-256", key.GetProperty("crv").GetString());
        Assert.Equal("sig", key.GetProperty("use").GetString());
        Assert.Equal("ES256", key.GetProperty("alg").GetString());
        Assert.Equal(ProofKeys.CreatePublicJwk(app.SigningKey).Kid, key.GetProperty("kid").GetString());
    }

    [Fact]
    public async Task JwksPublishesAdditionalKeysForRotation()
    {
        using var next = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var rotating = new IssuerApp(TestHost.Allowlist(host.AllowlistEntry()));
        var path = rotating.WritePublicKey("next.pem", next);
        using var rotatingWithKey = rotating.WithWebHostBuilder(b => b.UseSetting("Proof:AdditionalPublicKeyPaths:0", path));
        using var rotatingClient = rotatingWithKey.CreateClient();

        var keys = (await ReadJsonAsync(await rotatingClient.GetAsync(DiscoveryEndpoints.JwksPath, TestContext.Current.CancellationToken)))
            .GetProperty("keys").EnumerateArray().Select(k => k.GetProperty("kid").GetString()).ToList();

        Assert.Equal([ProofKeys.CreatePublicJwk(rotating.SigningKey).Kid, ProofKeys.CreatePublicJwk(next).Kid], keys);
    }

    [Fact]
    public async Task RefusesWrongGrantType()
    {
        var form = ExchangeForm(host.CreateToken());
        form["grant_type"] = "client_credentials";
        await AssertErrorAsync(await PostAsync(form), "unsupported_grant_type");
    }

    [Theory]
    [InlineData("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")]
    [InlineData("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")]
    [InlineData("actor_token", "x")]
    [InlineData("audience", "has space")]
    [InlineData("audience", "")]
    public async Task RefusesInvalidFields(string field, string value)
    {
        var form = ExchangeForm(host.CreateToken());
        form[field] = value;
        await AssertErrorAsync(await PostAsync(form), "invalid_request");
    }

    [Fact]
    public async Task RefusesMissingAudience() =>
        await AssertErrorAsync(await PostAsync(ExchangeForm(host.CreateToken(), audience: null)), "invalid_request");

    [Fact]
    public async Task RefusesMissingSubjectToken()
    {
        var form = ExchangeForm("");
        form.Remove("subject_token");
        await AssertErrorAsync(await PostAsync(form), "invalid_request");
    }

    [Fact]
    public async Task RefusesResourceParameter()
    {
        var form = ExchangeForm(host.CreateToken());
        form["resource"] = "https://service.test";
        await AssertErrorAsync(await PostAsync(form), "invalid_target");
    }

    [Fact]
    public async Task RefusesMoreThanOneAudience()
    {
        var form = ExchangeForm(host.CreateToken()).ToList();
        form.Add(new("audience", "second"));
        await AssertErrorAsync(await PostAsync(form), "invalid_request");
    }

    [Fact]
    public async Task RefusesQueryString() =>
        await AssertErrorAsync(await PostAsync(ExchangeForm(host.CreateToken()), TokenEndpoint.Path + "?audience=x"), "invalid_request");

    [Fact]
    public async Task RefusesJsonBody()
    {
        var response = await client.PostAsync(
            TokenEndpoint.Path,
            new StringContent(JsonSerializer.Serialize(ExchangeForm(host.CreateToken())), System.Text.Encoding.UTF8, "application/json"),
            TestContext.Current.CancellationToken);
        await AssertErrorAsync(response, "invalid_request");
    }

    [Fact]
    public async Task RefusesBadHostTokenWithGenericError()
    {
        var response = await PostAsync(ExchangeForm(new TestHost().CreateToken()));
        await AssertErrorAsync(response, "invalid_request");
        var body = await ReadJsonAsync(response);
        Assert.Equal("The request is invalid.", body.GetProperty("error_description").GetString());
    }

    [Fact]
    public async Task RefusesOversizedHostToken()
    {
        var token = host.CreateToken(c => c["padding"] = new string('a', HostTokenPolicy.MaxEncodedLength));
        await AssertErrorAsync(await PostAsync(ExchangeForm(token)), "invalid_request");
    }

    [Fact]
    public async Task AudienceAllowlistRefusesOtherAudiences()
    {
        using var restricted = new IssuerApp(
            TestHost.Allowlist(host.AllowlistEntry()),
            new() { ["Proof:AllowedAudiences:0"] = "puppet" });
        using var restrictedClient = restricted.CreateClient();
        var ct = TestContext.Current.CancellationToken;

        var refused = await restrictedClient.PostAsync(TokenEndpoint.Path, new FormUrlEncodedContent(ExchangeForm(host.CreateToken(), "step-ca")), ct);
        await AssertErrorAsync(refused, "invalid_target");

        var allowed = await restrictedClient.PostAsync(TokenEndpoint.Path, new FormUrlEncodedContent(ExchangeForm(host.CreateToken(), "puppet")), ct);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
    }

    [Fact]
    public async Task RateLimitsTokenRequests()
    {
        using var limited = new IssuerApp(TestHost.Allowlist(host.AllowlistEntry()), new() { ["Proof:TokenRequestsPerMinute"] = "2" });
        using var limitedClient = limited.CreateClient();
        var ct = TestContext.Current.CancellationToken;

        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 3; i++)
        {
            var response = await limitedClient.PostAsync(TokenEndpoint.Path, new FormUrlEncodedContent(ExchangeForm(host.CreateToken())), ct);
            statuses.Add(response.StatusCode);
        }

        Assert.Equal([HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.TooManyRequests], statuses);
    }

    /// <summary>Two requests through a proxy at 10.0.0.5, for two different callers, with a limit of one per minute.</summary>
    private async Task<List<HttpStatusCode>> PostAsTwoCallersAsync(Dictionary<string, string?> settings, string firstCaller = "192.0.2.1", string secondCaller = "192.0.2.2")
    {
        settings["Proof:TokenRequestsPerMinute"] = "1";
        using var proxied = new IssuerApp(TestHost.Allowlist(host.AllowlistEntry()), settings) { RemoteAddress = IPAddress.Parse("10.0.0.5") };
        using var proxiedClient = proxied.CreateClient();
        var ct = TestContext.Current.CancellationToken;

        var statuses = new List<HttpStatusCode>();
        foreach (var caller in new[] { firstCaller, secondCaller })
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, TokenEndpoint.Path)
            {
                Content = new FormUrlEncodedContent(ExchangeForm(host.CreateToken())),
            };
            // A caller's own spoofed entry first, then the one the proxy appends.
            request.Headers.Add("X-Forwarded-For", $"203.0.113.9, {caller}");
            statuses.Add((await proxiedClient.SendAsync(request, ct)).StatusCode);
        }

        return statuses;
    }

    [Fact]
    public async Task RateLimitsByTheAddressATrustedProxyForwards()
    {
        Assert.Equal(
            [HttpStatusCode.OK, HttpStatusCode.OK],
            await PostAsTwoCallersAsync(new() { ["Proof:TrustedProxies:0"] = "10.0.0.0/24" }));
        Assert.Equal(
            [HttpStatusCode.OK, HttpStatusCode.TooManyRequests],
            await PostAsTwoCallersAsync(new() { ["Proof:TrustedProxies:0"] = "10.0.0.5" }, secondCaller: "192.0.2.1"));
    }

    [Fact]
    public async Task IgnoresForwardedAddressesFromUntrustedConnections()
    {
        Assert.Equal([HttpStatusCode.OK, HttpStatusCode.TooManyRequests], await PostAsTwoCallersAsync(new()));
        Assert.Equal(
            [HttpStatusCode.OK, HttpStatusCode.TooManyRequests],
            await PostAsTwoCallersAsync(new() { ["Proof:TrustedProxies:0"] = "10.0.1.0/24" }));
    }

    [Fact]
    public void RefusesToStartWithAspNetCoreForwardedHeadersSwitch()
    {
        using var bad = new IssuerApp(TestHost.Allowlist(host.AllowlistEntry()), new() { ["ForwardedHeaders_Enabled"] = "true" });
        Assert.ThrowsAny<Exception>(() => bad.CreateClient());
    }

    [Fact]
    public async Task ReadyOnlyAfterAllowlistLoads()
    {
        var ct = TestContext.Current.CancellationToken;
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/healthz/ready", ct)).StatusCode);

        using var broken = new IssuerApp("version: 1\nhosts: [");
        using var brokenClient = broken.CreateClient();
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await brokenClient.GetAsync("/healthz/ready", ct)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await brokenClient.GetAsync("/healthz/live", ct)).StatusCode);
    }

    [Theory]
    [InlineData("Proof:IssuerUrl", "http://proof.test")]
    [InlineData("Proof:IssuerUrl", "https://proof.test/")]
    [InlineData("Proof:IssuedTokenLifetime", "00:11:00")]
    [InlineData("Proof:TrustedProxies:0", "ingress")]
    [InlineData("Proof:TrustedProxies:0", "10.0.0.1/8")]
    public void RefusesToStartWithInvalidOptions(string key, string value)
    {
        using var bad = new IssuerApp(TestHost.Allowlist(host.AllowlistEntry()), new() { [key] = value });
        Assert.ThrowsAny<Exception>(() => bad.CreateClient());
    }

    [Fact]
    public void RefusesToStartWithPublicOnlySigningKey()
    {
        using var bad = new IssuerApp(TestHost.Allowlist(host.AllowlistEntry()));
        File.WriteAllText(bad.SigningKeyPath, bad.SigningKey.ExportSubjectPublicKeyInfoPem());
        Assert.ThrowsAny<Exception>(() => bad.CreateClient());
    }
}
