using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Proof.Shared;

namespace Proof.Metadata;

/// <summary>
/// The local HTTP API (Design.md 16.4): EC2's instance metadata paths for cloud-init and Cloudbase-Init, plus
/// <c>/proof/v1/provisioning</c> to report the end of provisioning, all translated to requests to the host.
/// </summary>
public sealed partial class MetadataApi(IHostChannel host, TimeProvider time, ILogger<MetadataApi> logger)
{
    public const int DefaultPort = 8169;

    public const string TokenPath = "/latest/api/token";
    public const string ProvisioningPath = "/proof/v1/provisioning";

    private const string TokenHeader = "X-aws-ec2-metadata-token";
    private const string TokenTtlHeader = "X-aws-ec2-metadata-token-ttl-seconds";
    private const int MaxTokenTtlSeconds = 21600;

    // Long enough to serve one crawl of many paths from one answer, and short enough that an operator's edit shows soon.
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromSeconds(5);

    /// <summary>The versions listed at the root. Any version-shaped path is served, since the tree does not vary by version.</summary>
    private static readonly string[] Versions = ["2009-04-04", "2016-09-02", "2018-09-24", "2021-03-23", "latest"];

    private readonly byte[] tokenKey = RandomNumberGenerator.GetBytes(32);
    private readonly SemaphoreSlim cacheGate = new(1, 1);
    private MetadataResponse? cached;
    private DateTimeOffset cachedUntil;

    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}$|^latest$")]
    private static partial Regex VersionPattern();

    public async Task HandleAsync(HttpContext context)
    {
        if (RefuseReason(context.Request) is { } reason)
        {
            await WriteAsync(context, StatusCodes.Status403Forbidden, reason);
            return;
        }

        var (method, path) = (context.Request.Method, context.Request.Path.Value ?? "/");
        if (path == TokenPath)
        {
            await (method == HttpMethods.Put ? IssueTokenAsync(context) : WriteAsync(context, StatusCodes.Status405MethodNotAllowed, "Use PUT."));
        }
        else if (path == ProvisioningPath || path.StartsWith(ProvisioningPath + "/", StringComparison.Ordinal))
        {
            await ProvisioningAsync(context, method, path[ProvisioningPath.Length..].Trim('/'));
        }
        else if (method is not ("GET" or "HEAD"))
        {
            await WriteAsync(context, StatusCodes.Status405MethodNotAllowed, "Use GET.");
        }
        else if (!HasAcceptableToken(context.Request))
        {
            // As on EC2: no token is allowed, and a wrong one is refused so the caller asks for a new one.
            await WriteAsync(context, StatusCodes.Status401Unauthorized, "The token is not valid.");
        }
        else
        {
            await ServeTreeAsync(context, path);
        }
    }

    /// <summary>
    /// Requests that came through something other than a local program, whatever socket they arrived on. Web pages in
    /// a browser in this VM can reach loopback: a page that rebinds its name to 127.0.0.1 sends its own name as Host,
    /// and any cross-origin POST carries Origin. Forwarding proxies add X-Forwarded-For, which EC2 refuses as well.
    /// </summary>
    private static string? RefuseReason(HttpRequest request)
    {
        if (request.Headers.ContainsKey("X-Forwarded-For"))
        {
            return "Requests through a proxy are refused.";
        }

        if (request.Headers.ContainsKey("Origin"))
        {
            return "Requests from web pages are refused.";
        }

        var hostname = request.Host.Host;
        return hostname == "localhost" || (IPAddress.TryParse(hostname, out var address) && IPAddress.IsLoopback(address))
            ? null
            : "The Host header must name this machine's loopback address.";
    }

    private async Task ServeTreeAsync(HttpContext context, string path)
    {
        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0)
        {
            await WriteAsync(context, StatusCodes.Status200OK, string.Join('\n', Versions));
            return;
        }

        if (!VersionPattern().IsMatch(segments[0]))
        {
            await WriteAsync(context, StatusCodes.Status404NotFound, "Not found.");
            return;
        }

        MetadataResponse response;
        try
        {
            response = await GetAsync(context.RequestAborted);
        }
        catch (IOException ex)
        {
            logger.LogWarning("Cannot read metadata from the host: {Error}", ex.Message);
            await WriteAsync(context, StatusCodes.Status503ServiceUnavailable, "The Hyper-V host's metadata service cannot be reached.");
            return;
        }

        switch (response.Status)
        {
            case MetadataResponseStatus.Ok:
                break;
            case MetadataResponseStatus.NotEnrolled:
                // Only where the host is set to require a block. Cloud-init retries this until its max_wait.
                await WriteAsync(context, StatusCodes.Status404NotFound, "This VM has no metadata block, and its host requires one.");
                return;
            default:
                await WriteAsync(context, StatusCodes.Status503ServiceUnavailable, "The host cannot serve this VM's metadata. Its log says why.");
                return;
        }

        var rest = segments.Skip(1).ToArray();
        switch (rest)
        {
            case []:
                await WriteAsync(context, StatusCodes.Status200OK, response.UserData is null ? "meta-data" : "meta-data\nuser-data");
                break;
            case ["user-data"] when response.UserData is { } userData:
                context.Response.ContentType = "application/octet-stream";
                await context.Response.Body.WriteAsync(Encoding.UTF8.GetBytes(userData), context.RequestAborted);
                break;
            case ["meta-data", .. var inner]:
                switch (Ec2Tree.Find(Ec2Tree.Build(response.InstanceId!, response.MetaData), inner))
                {
                    case Ec2Node.Leaf leaf:
                        await WriteAsync(context, StatusCodes.Status200OK, leaf.Text);
                        break;
                    case Ec2Node.Directory directory:
                        await WriteAsync(context, StatusCodes.Status200OK, Ec2Tree.List(directory));
                        break;
                    default:
                        await WriteAsync(context, StatusCodes.Status404NotFound, "Not found.");
                        break;
                }

                break;
            default:
                await WriteAsync(context, StatusCodes.Status404NotFound, "Not found.");
                break;
        }
    }

    private async Task ProvisioningAsync(HttpContext context, string method, string action)
    {
        MetadataRequest request;
        switch (action)
        {
            case "" when method is "GET" or "HEAD":
                request = new MetadataRequest(MetadataOperations.Get);
                break;
            case ProvisioningStatus.Complete or ProvisioningStatus.Failed when method == HttpMethods.Post:
                // The body is ignored: cloud-init's phone_home module posts its keys and hostname, which nothing needs.
                request = new MetadataRequest(MetadataOperations.Finish, action);
                break;
            default:
                await WriteAsync(context, StatusCodes.Status404NotFound, "Not found.");
                return;
        }

        MetadataResponse response;
        try
        {
            response = await SendFreshAsync(request, context.RequestAborted);
        }
        catch (IOException ex)
        {
            logger.LogWarning("Cannot reach the host: {Error}", ex.Message);
            await WriteAsync(context, StatusCodes.Status503ServiceUnavailable, "The Hyper-V host's metadata service cannot be reached.");
            return;
        }

        var (status, text) = response.Status switch
        {
            MetadataResponseStatus.Ok => (StatusCodes.Status200OK, response.Provisioning ?? ""),
            MetadataResponseStatus.NotEnrolled => (StatusCodes.Status404NotFound, "This VM has no metadata block, and its host requires one."),
            _ => (StatusCodes.Status503ServiceUnavailable, "The host could not do this. Its log says why."),
        };
        await WriteAsync(context, status, text);
    }

    /// <summary>Bypasses the cache, and drops it: after a finish, sensitive values must stop being served at once.</summary>
    private async Task<MetadataResponse> SendFreshAsync(MetadataRequest request, CancellationToken cancellationToken)
    {
        await cacheGate.WaitAsync(cancellationToken);
        try
        {
            cached = null;
            return await host.SendAsync(request, cancellationToken);
        }
        finally
        {
            cacheGate.Release();
        }
    }

    private async Task<MetadataResponse> GetAsync(CancellationToken cancellationToken)
    {
        await cacheGate.WaitAsync(cancellationToken);
        try
        {
            if (cached is not null && time.GetUtcNow() < cachedUntil)
            {
                return cached;
            }

            var response = await host.SendAsync(new MetadataRequest(MetadataOperations.Get), cancellationToken);
            // Trouble is not kept, so a retry sees a fix at once.
            cached = response.Status is MetadataResponseStatus.Ok or MetadataResponseStatus.NotEnrolled ? response : null;
            cachedUntil = time.GetUtcNow() + CacheLifetime;
            return response;
        }
        finally
        {
            cacheGate.Release();
        }
    }

    /// <summary>
    /// IMDSv2 sessions, which cloud-init asks for first. A token needs a PUT with a custom header, which a request
    /// forged by another program or a web page cannot usually send. Tokens are the expiry and its HMAC, so nothing is
    /// stored and any number of callers cost nothing. A restart makes them invalid; callers get a 401 and ask again.
    /// </summary>
    private async Task IssueTokenAsync(HttpContext context)
    {
        if (!int.TryParse(context.Request.Headers[TokenTtlHeader], NumberStyles.None, CultureInfo.InvariantCulture, out var ttl)
            || ttl is < 1 or > MaxTokenTtlSeconds)
        {
            await WriteAsync(context, StatusCodes.Status400BadRequest, $"{TokenTtlHeader} must be 1 to {MaxTokenTtlSeconds}.");
            return;
        }

        var expires = time.GetUtcNow().ToUnixTimeSeconds() + ttl;
        context.Response.Headers[TokenTtlHeader] = ttl.ToString(CultureInfo.InvariantCulture);
        await WriteAsync(context, StatusCodes.Status200OK, $"{expires}.{Sign(expires)}");
    }

    private bool HasAcceptableToken(HttpRequest request)
    {
        if (!request.Headers.TryGetValue(TokenHeader, out var values))
        {
            return true;
        }

        var parts = values.ToString().Split('.');
        return parts.Length == 2
            && long.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var expires)
            && expires > time.GetUtcNow().ToUnixTimeSeconds()
            && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(parts[1]), Encoding.ASCII.GetBytes(Sign(expires)));
    }

    private string Sign(long expires) =>
        WebEncoders.Base64UrlEncode(HMACSHA256.HashData(tokenKey, Encoding.ASCII.GetBytes(expires.ToString(CultureInfo.InvariantCulture))));

    private static async Task WriteAsync(HttpContext context, int status, string text)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "text/plain; charset=utf-8";
        await context.Response.WriteAsync(text, context.RequestAborted);
    }
}
