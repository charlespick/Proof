using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Proof.Shared;

namespace Proof.Client;

/// <summary>A JWT the issuer returned, with the expiry it states.</summary>
public sealed record IssuedToken(string Token, DateTimeOffset Expires);

/// <summary>The issuer answered, but not with a token.</summary>
public sealed class TokenExchangeException(string message, string? error = null) : Exception(message)
{
    /// <summary>The OAuth <c>error</c> code, if the issuer sent one.</summary>
    public string? Error { get; } = error;
}

/// <summary>Trades a host token for an audience-specific JWT at the issuer's <c>/token</c> (RFC 8693, Design.md 6.3).</summary>
public sealed class TokenExchangeClient(HttpClient http, Uri endpoint)
{
    /// <summary>Responses larger than this are refused. An issued JWT is well under 2 KB.</summary>
    public const int MaxResponseBytes = 64 * 1024;

    public Uri Endpoint => endpoint;

    public async Task<IssuedToken> ExchangeAsync(string hostToken, string audience, CancellationToken cancellationToken)
    {
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchange.GrantType,
            ["subject_token"] = hostToken,
            ["subject_token_type"] = TokenExchange.JwtTokenType,
            ["requested_token_type"] = TokenExchange.JwtTokenType,
            ["audience"] = audience,
        });
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = content };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        var body = await ReadBodyAsync(response, cancellationToken);

        JsonElement json;
        try
        {
            using var document = JsonDocument.Parse(body);
            json = document.RootElement.Clone();
        }
        catch (JsonException)
        {
            throw new TokenExchangeException($"The issuer answered HTTP {(int)response.StatusCode} {response.ReasonPhrase} without a JSON body.");
        }

        if (json.ValueKind != JsonValueKind.Object)
        {
            throw new TokenExchangeException($"The issuer answered HTTP {(int)response.StatusCode} with unexpected JSON.");
        }

        if (!response.IsSuccessStatusCode)
        {
            var error = String(json, "error");
            var description = String(json, "error_description");
            throw new TokenExchangeException(
                $"The issuer refused the exchange: HTTP {(int)response.StatusCode}, {error ?? "no error code"}{(description is null ? "" : $" ({description})")}.",
                error);
        }

        // token_type is N_A for a JWT (RFC 8693 section 2.2.1), so it is not checked; access_token is the token.
        if (String(json, "issued_token_type") != TokenExchange.JwtTokenType || String(json, "access_token") is not { Length: > 0 } token)
        {
            throw new TokenExchangeException("The issuer's response holds no JWT.");
        }

        // Consumers verify the token; the client only reads its expiry, for messages and for callers that schedule renewal.
        DateTimeOffset expires;
        try
        {
            expires = new DateTimeOffset(new JsonWebToken(token).ValidTo, TimeSpan.Zero);
        }
        catch (Exception ex) when (ex is ArgumentException or Microsoft.IdentityModel.Tokens.SecurityTokenMalformedException)
        {
            throw new TokenExchangeException("The issuer's response holds a malformed JWT.");
        }

        return new IssuedToken(token, expires);
    }

    private static string? String(JsonElement json, string name) =>
        json.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static async Task<byte[]> ReadBodyAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength is > MaxResponseBytes)
        {
            throw new TokenExchangeException($"The issuer's response is {response.Content.Headers.ContentLength} bytes, too large to be a token.");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken)) > 0)
        {
            if (buffer.Length + read > MaxResponseBytes)
            {
                throw new TokenExchangeException("The issuer's response is too large to be a token.");
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    /// <summary>
    /// An HTTP client for the issuer. It never follows redirects, so the host token goes only to the configured
    /// endpoint. With a CA bundle, the issuer's certificate must chain to one of its certificates.
    /// </summary>
    public static HttpClient CreateHttpClient(X509Certificate2Collection? caBundle)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            AutomaticDecompression = DecompressionMethods.None,
        };
        if (caBundle is not null)
        {
            handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
                ValidateWithBundle(caBundle, certificate, chain, errors);
        }

        var version = typeof(TokenExchangeClient).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0";
        var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("proof", version.Split('+')[0]));
        return client;
    }

    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

    /// <summary>
    /// TLS server validation against <paramref name="roots"/> only. The platform has already checked the host name;
    /// any error other than an untrusted chain fails. The chain is then rebuilt with the bundle as the only trust.
    /// </summary>
    public static bool ValidateWithBundle(X509Certificate2Collection roots, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (certificate is null || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None)
        {
            return false;
        }

        using var leaf = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
        using var custom = new X509Chain();
        custom.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        custom.ChainPolicy.CustomTrustStore.AddRange(roots);
        // As SslStream does by default: internal CAs often publish no revocation data.
        custom.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        custom.ChainPolicy.ApplicationPolicy.Add(new Oid(ServerAuthenticationOid));
        if (chain is not null)
        {
            // Intermediates the server sent.
            foreach (var element in chain.ChainElements)
            {
                custom.ChainPolicy.ExtraStore.Add(element.Certificate);
            }
        }

        return custom.Build(leaf);
    }
}
