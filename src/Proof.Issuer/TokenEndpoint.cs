using System.Text.Json;
using Microsoft.Extensions.Options;
using Proof.Shared;

namespace Proof.Issuer;

/// <summary>
/// <c>POST /token</c>: RFC 8693 token exchange (Design.md 6.3). The signed host token is the only credential.
/// Callers get a generic error; the reason goes to the log.
/// </summary>
public static class TokenEndpoint
{
    public const string Path = "/token";
    public const string RateLimitPolicy = "token";

    /// <summary>Bodies larger than this are refused. A host token is at most 4 KB.</summary>
    public const int MaxRequestBytes = 16 * 1024;

    public const int MaxAudienceLength = 256;

    internal static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };

    // RFC 8693 section 2.2.2: an invalid or unacceptable subject_token is invalid_request, not invalid_grant.
    private const string InvalidRequest = "invalid_request";
    private const string InvalidTarget = "invalid_target";
    private const string UnsupportedGrantType = "unsupported_grant_type";

    public static bool IsWellFormedAudience(string? audience) =>
        !string.IsNullOrEmpty(audience)
        && audience.Length <= MaxAudienceLength
        && !audience.Any(c => char.IsWhiteSpace(c) || char.IsControl(c));

    public static async Task<IResult> HandleAsync(
        HttpContext http,
        HostTokenValidator validator,
        TokenMinter minter,
        IOptions<IssuerOptions> options,
        IssuerMetrics metrics,
        ILoggerFactory loggerFactory)
    {
        var log = new ExchangeLog(loggerFactory.CreateLogger(typeof(TokenEndpoint).FullName!), metrics, http);
        var request = http.Request;

        // Parameters belong in the body. Refusing a query string keeps tokens out of URLs and access logs.
        if (request.QueryString.HasValue)
        {
            return log.Refuse(InvalidRequest, "query string present");
        }

        if (!request.HasFormContentType)
        {
            return log.Refuse(InvalidRequest, "not form-encoded");
        }

        if (request.ContentLength is > MaxRequestBytes)
        {
            return log.Refuse(InvalidRequest, "body too large");
        }

        IFormCollection form;
        try
        {
            form = await request.ReadFormAsync(http.RequestAborted);
        }
        catch (Exception ex) when (ex is InvalidDataException or BadHttpRequestException or IOException)
        {
            return log.Refuse(InvalidRequest, $"unreadable form ({ex.GetType().Name})");
        }

        // RFC 6749 section 3.2: parameters must not repeat. v1 also accepts exactly one audience.
        foreach (var field in form)
        {
            if (field.Value.Count != 1)
            {
                return log.Refuse(InvalidRequest, $"'{field.Key}' repeated");
            }
        }

        string? Field(string name) => form.TryGetValue(name, out var value) ? value.ToString() : null;

        if (Field("grant_type") != TokenExchange.GrantType)
        {
            return log.Refuse(UnsupportedGrantType, "wrong grant_type");
        }

        if (Field("subject_token_type") != TokenExchange.JwtTokenType)
        {
            return log.Refuse(InvalidRequest, "wrong subject_token_type");
        }

        if (Field("requested_token_type") is { } requested && requested != TokenExchange.JwtTokenType)
        {
            return log.Refuse(InvalidRequest, "unsupported requested_token_type");
        }

        if (form.ContainsKey("actor_token") || form.ContainsKey("actor_token_type"))
        {
            return log.Refuse(InvalidRequest, "delegation not supported");
        }

        if (form.ContainsKey("resource"))
        {
            return log.Refuse(InvalidTarget, "resource not supported");
        }

        var audience = Field("audience");
        if (!IsWellFormedAudience(audience))
        {
            return log.Refuse(InvalidRequest, "missing or malformed audience");
        }

        log.Audience = audience;
        var allowed = options.Value.AllowedAudiences;
        if (allowed.Count > 0 && !allowed.Contains(audience!, StringComparer.Ordinal))
        {
            return log.Refuse(InvalidTarget, "audience not allowed");
        }

        var subjectToken = Field("subject_token");
        if (string.IsNullOrEmpty(subjectToken))
        {
            return log.Refuse(InvalidRequest, "missing subject_token");
        }

        var result = await validator.ValidateAsync(subjectToken);
        log.HostKid = result.Kid;
        if (!result.IsValid)
        {
            return log.Refuse(InvalidRequest, $"host token {result.Failure}{(result.Detail is null ? "" : $" ({result.Detail})")}");
        }

        var identity = result.Identity!;
        log.Subject = identity.VmId;
        log.HostJti = identity.Jti;

        var token = minter.Mint(identity, audience!);
        log.Succeed();

        http.Response.Headers.CacheControl = "no-store";
        http.Response.Headers.Pragma = "no-cache";
        return Results.Json(
            new TokenResponse(token, TokenExchange.JwtTokenType, TokenExchange.NotApplicableTokenType, (int)minter.Lifetime.TotalSeconds),
            Json);
    }

    private sealed record TokenResponse(string AccessToken, string IssuedTokenType, string TokenType, int ExpiresIn);

    private sealed record ErrorResponse(string Error, string ErrorDescription);

    /// <summary>One structured log line per exchange (Design.md 8). Never tokens, keys or claim sets.</summary>
    private sealed class ExchangeLog(ILogger logger, IssuerMetrics metrics, HttpContext http)
    {
        public string? Audience { get; set; }
        public string? HostKid { get; set; }
        public string? HostJti { get; set; }
        public string? Subject { get; set; }

        public IResult Refuse(string error, string reason)
        {
            metrics.Exchange(error);
            logger.LogWarning(
                "Token exchange refused: {Error}, {Reason}. Audience {Audience}, host kid {HostKid}, source {Source}",
                error, reason, Audience, HostKid, http.Connection.RemoteIpAddress);

            http.Response.Headers.CacheControl = "no-store";
            return Results.Json(new ErrorResponse(error, Describe(error)), Json, statusCode: StatusCodes.Status400BadRequest);
        }

        public void Succeed()
        {
            metrics.Exchange("success");
            logger.LogInformation(
                "Token exchange issued: sub {Subject}, audience {Audience}, host kid {HostKid}, host token jti {HostJti}, source {Source}",
                Subject, Audience, HostKid, HostJti, http.Connection.RemoteIpAddress);
        }

        private static string Describe(string error) => error switch
        {
            UnsupportedGrantType => "The grant type is not supported.",
            InvalidTarget => "A token cannot be issued for the requested target.",
            _ => "The request is invalid.",
        };
    }
}
