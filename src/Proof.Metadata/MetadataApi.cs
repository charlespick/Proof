using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;
using Proof.Shared;

namespace Proof.Metadata;

/// <summary>
/// The local HTTP API: OpenStack's metadata paths for cloud-init and Cloudbase-Init, plus
/// <c>/proof/v1/provisioning</c> to report the end of provisioning, all translated to requests to the host.
/// </summary>
/// <remarks>
/// Only <c>latest</c> is served. Cloudbase-Init posts the password it sets back to the metadata service when the
/// version <c>2013-04-04</c> exists, and nothing a guest sends may be stored, so no dated version is listed or served.
/// </remarks>
public sealed class MetadataApi(IHostChannel host, TimeProvider time, ILogger<MetadataApi> logger)
{
    public const int DefaultPort = 8169;

    public const string OpenStackPath = "/openstack";
    public const string ProvisioningPath = "/proof/v1/provisioning";

    private const string JsonContentType = "application/json";

    // Long enough to serve one crawl of many paths from one answer, and short enough that an operator's edit shows soon.
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromSeconds(5);

    private readonly SemaphoreSlim cacheGate = new(1, 1);
    private MetadataResponse? cached;
    private DateTimeOffset cachedUntil;

    /// <summary>What a path under <c>/openstack</c> names.</summary>
    private enum Document
    {
        Versions,
        Files,
        MetaData,
        NetworkData,
        UserData,
    }

    public async Task HandleAsync(HttpContext context)
    {
        if (RefuseReason(context.Request) is { } reason)
        {
            await WriteAsync(context, StatusCodes.Status403Forbidden, reason);
            return;
        }

        var (method, path) = (context.Request.Method, context.Request.Path.Value ?? "/");
        if (path == ProvisioningPath || path.StartsWith(ProvisioningPath + "/", StringComparison.Ordinal))
        {
            await ProvisioningAsync(context, method, path[ProvisioningPath.Length..].Trim('/'));
        }
        else if (method is not ("GET" or "HEAD"))
        {
            // Cloudbase-Init's password post among them. It only tries one where the dated version exists.
            await WriteAsync(context, StatusCodes.Status405MethodNotAllowed, "Use GET.");
        }
        else
        {
            switch (path.Split('/', StringSplitOptions.RemoveEmptyEntries))
            {
                case []:
                    await WriteAsync(context, StatusCodes.Status200OK, OpenStackPath.TrimStart('/'));
                    break;
                case ["openstack", .. var rest] when Find(rest) is { } document:
                    await ServeAsync(context, document);
                    break;
                default:
                    await WriteAsync(context, StatusCodes.Status404NotFound, "Not found.");
                    break;
            }
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

    /// <summary>The document a path names, decided before the host is asked, so a path that can't exist never waits on it.</summary>
    private static Document? Find(string[] segments) => segments switch
    {
        [] => Document.Versions,
        [OpenStackDocuments.Latest] => Document.Files,
        [OpenStackDocuments.Latest, OpenStackDocuments.MetaData] => Document.MetaData,
        [OpenStackDocuments.Latest, OpenStackDocuments.NetworkData] => Document.NetworkData,
        [OpenStackDocuments.Latest, OpenStackDocuments.UserData] => Document.UserData,
        _ => null,
    };

    private async Task ServeAsync(HttpContext context, Document document)
    {
        // Even the version list waits on the host: cloud-init polls it until max_wait, then reads the rest at once.
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

        switch (document)
        {
            case Document.Versions:
                await WriteAsync(context, StatusCodes.Status200OK, OpenStackDocuments.Latest);
                break;
            case Document.Files:
                string?[] files =
                [
                    OpenStackDocuments.MetaData,
                    response.NetworkData is null ? null : OpenStackDocuments.NetworkData,
                    response.UserData is null ? null : OpenStackDocuments.UserData,
                ];
                await WriteAsync(context, StatusCodes.Status200OK, string.Join('\n', files.OfType<string>()));
                break;
            case Document.MetaData:
                await WriteBytesAsync(context, JsonContentType, OpenStackDocuments.BuildMetaData(response.InstanceId!, response.MetaData));
                break;
            case Document.NetworkData when response.NetworkData is { } networkData:
                await WriteBytesAsync(context, JsonContentType, Encoding.UTF8.GetBytes(networkData));
                break;
            case Document.UserData when response.UserData is { } userData:
                await WriteBytesAsync(context, "application/octet-stream", Encoding.UTF8.GetBytes(userData));
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

    private static async Task WriteBytesAsync(HttpContext context, string contentType, byte[] body)
    {
        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = contentType;
        await context.Response.Body.WriteAsync(body, context.RequestAborted);
    }

    private static async Task WriteAsync(HttpContext context, int status, string text)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "text/plain; charset=utf-8";
        await context.Response.WriteAsync(text, context.RequestAborted);
    }
}
