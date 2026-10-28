using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http.Features;
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

// Behind the ingress, RemoteIpAddress is the caller only if forwarded headers are trusted
// (for example ASPNETCORE_FORWARDEDHEADERS_ENABLED=true when only the ingress can reach the pod).
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

app.UseRateLimiter();

app.MapPost(TokenEndpoint.Path, TokenEndpoint.HandleAsync)
    .RequireRateLimiting(TokenEndpoint.RateLimitPolicy)
    .DisableAntiforgery();
app.MapDiscovery();
app.MapHealthChecks("/healthz/live", new HealthCheckOptions { Predicate = _ => false });
app.MapHealthChecks("/healthz/ready", new HealthCheckOptions { Predicate = check => check.Tags.Contains("ready") });

app.Run();
