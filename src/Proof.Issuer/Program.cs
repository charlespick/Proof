using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Proof.Issuer;
using Proof.Issuer.Allowlist;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.AddServerHeader = false;
    kestrel.Limits.MaxRequestBodySize = TokenEndpoint.MaxRequestBytes;
});

builder.Services.Configure<FormOptions>(form =>
{
    form.ValueCountLimit = 16;
    form.KeyLengthLimit = 64;
    form.ValueLengthLimit = TokenEndpoint.MaxRequestBytes;
    form.MultipartBodyLengthLimit = TokenEndpoint.MaxRequestBytes;
});

builder.Services.AddOptions<IssuerOptions>()
    .BindConfiguration(IssuerOptions.SectionName)
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<IssuerOptions>, IssuerOptionsValidator>();

builder.Services.TryAddSingleton(TimeProvider.System);
builder.Services.AddMetrics();
builder.Services.AddSingleton<IssuerMetrics>();
builder.Services.AddSingleton<SigningKeys>();
builder.Services.AddSingleton<AllowlistMonitor>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<AllowlistMonitor>());
builder.Services.AddSingleton<HostTokenValidator>();
builder.Services.AddSingleton<TokenMinter>();

builder.Services.AddHealthChecks()
    .AddCheck<AllowlistReadinessCheck>("allowlist", tags: ["ready"]);

// ASP.NET Core's own switch trusts X-Forwarded-For from any address that can reach the pod, so a caller could pick
// its own rate-limit partition. Proof:TrustedProxies trusts only the named proxies.
if (string.Equals(builder.Configuration["ForwardedHeaders_Enabled"], "true", StringComparison.OrdinalIgnoreCase))
{
    throw new InvalidOperationException(
        "ASPNETCORE_FORWARDEDHEADERS_ENABLED trusts forwarded headers from any address. Unset it and list the ingress in Proof:TrustedProxies instead.");
}

// Behind the ingress, RemoteIpAddress is the caller only once forwarded headers from Proof:TrustedProxies are applied.
builder.Services.AddRateLimiter(limiter =>
{
    limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    limiter.AddPolicy(TokenEndpoint.RateLimitPolicy, http =>
    {
        var perMinute = http.RequestServices.GetRequiredService<IOptions<IssuerOptions>>().Value.TokenRequestsPerMinute;
        return RateLimitPartition.GetFixedWindowLimiter(
            http.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = perMinute,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
            });
    });
});

var app = builder.Build();

// Fail at startup, not on the first request, if the signing key is missing or wrong.
app.Services.GetRequiredService<SigningKeys>();

var trustedProxies = app.Services.GetRequiredService<IOptions<IssuerOptions>>().Value.TrustedProxies;
if (trustedProxies.Count > 0)
{
    // Only the source address: the issuer URL is configured, never taken from Host or X-Forwarded-Proto.
    // ForwardLimit 1 takes only the rightmost entry, the one the trusted proxy added.
    var forwarded = new ForwardedHeadersOptions { ForwardedHeaders = ForwardedHeaders.XForwardedFor, ForwardLimit = 1 };
    forwarded.KnownProxies.Clear();
    forwarded.KnownIPNetworks.Clear();
    foreach (var proxy in trustedProxies)
    {
        IssuerOptions.TryParseNetwork(proxy, out var network);
        forwarded.KnownIPNetworks.Add(network);
    }

    app.UseForwardedHeaders(forwarded);
}

app.UseRateLimiter();

app.MapPost(TokenEndpoint.Path, TokenEndpoint.HandleAsync)
    .RequireRateLimiting(TokenEndpoint.RateLimitPolicy)
    .DisableAntiforgery();
app.MapDiscovery();
app.MapHealthChecks("/healthz/live", new HealthCheckOptions { Predicate = _ => false });
app.MapHealthChecks("/healthz/ready", new HealthCheckOptions { Predicate = check => check.Tags.Contains("ready") });

app.Run();
