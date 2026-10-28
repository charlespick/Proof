using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Proof.Shared;

namespace Proof.Client;

/// <summary>A configuration file that is missing or wrong.</summary>
public sealed class ClientConfigException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// The client's settings: a small JSON file baked into the image (Design.md 9). The issuer URL is configured, never
/// learned from KVP.
/// </summary>
public sealed class ClientOptions
{
    /// <summary>The issuer URL, exactly as the issuer and the hosts are configured. Host tokens carry it as <c>aud</c>.</summary>
    public required string IssuerUrl { get; init; }

    /// <summary>Where token exchanges go. Defaults to <c>/token</c> under the issuer URL; set it when <c>/token</c> is served at an internal name.</summary>
    public required Uri TokenEndpoint { get; init; }

    /// <summary>A PEM file of CA certificates. When set, the issuer's TLS certificate must chain to one of these, and the system store is not used.</summary>
    public string? CaBundlePath { get; init; }

    public static string DefaultPath =>
        OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Proof", "config.json")
            : "/etc/proof/config.json";

    private static readonly JsonDocumentOptions JsonOptions = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    public static ClientOptions Load(string path)
    {
        string text;
        try
        {
            text = File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            throw new ClientConfigException($"No configuration at {path}. Create it with: {{ \"IssuerUrl\": \"https://id.example\" }}", ex);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ClientConfigException($"Cannot read {path}: {ex.Message}", ex);
        }

        try
        {
            return Parse(text, Path.GetDirectoryName(Path.GetFullPath(path))!);
        }
        catch (ClientConfigException ex)
        {
            throw new ClientConfigException($"{path}: {ex.Message}", ex.InnerException);
        }
    }

    /// <summary>Parses the settings. A relative <c>CaBundlePath</c> is taken from <paramref name="baseDirectory"/>.</summary>
    public static ClientOptions Parse(string json, string baseDirectory)
    {
        string? issuerUrl = null, tokenEndpoint = null, caBundlePath = null;
        try
        {
            using var document = JsonDocument.Parse(json, JsonOptions);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new ClientConfigException("The settings must be a JSON object.");
            }

            foreach (var property in document.RootElement.EnumerateObject())
            {
                var value = property.Value.ValueKind switch
                {
                    JsonValueKind.String => property.Value.GetString(),
                    JsonValueKind.Null => null,
                    _ => throw new ClientConfigException($"{property.Name} must be a string."),
                };

                // Unknown names are refused, so a misspelled setting is not silently ignored.
                switch (property.Name.ToLowerInvariant())
                {
                    case "issuerurl":
                        issuerUrl = value;
                        break;
                    case "tokenendpoint":
                        tokenEndpoint = value;
                        break;
                    case "cabundlepath":
                        caBundlePath = value;
                        break;
                    default:
                        throw new ClientConfigException($"Unknown setting '{property.Name}'. Settings are IssuerUrl, TokenEndpoint and CaBundlePath.");
                }
            }
        }
        catch (JsonException ex)
        {
            throw new ClientConfigException($"Not valid JSON: {ex.Message}", ex);
        }

        if (!ProofIssuerUrl.IsValid(issuerUrl))
        {
            throw new ClientConfigException("IssuerUrl must be an absolute https URL with no trailing slash, query or fragment, matching the issuer's.");
        }

        Uri endpoint;
        if (string.IsNullOrEmpty(tokenEndpoint))
        {
            endpoint = new Uri(issuerUrl + TokenExchange.EndpointPath);
        }
        else if (!Uri.TryCreate(tokenEndpoint, UriKind.Absolute, out endpoint!)
            || endpoint.Scheme != Uri.UriSchemeHttps
            || !string.IsNullOrEmpty(endpoint.Query)
            || !string.IsNullOrEmpty(endpoint.UserInfo))
        {
            // The host token is the credential, so it only travels over TLS and never in a URL.
            throw new ClientConfigException("TokenEndpoint must be an absolute https URL with no query or user info.");
        }

        if (!string.IsNullOrEmpty(caBundlePath))
        {
            caBundlePath = Path.GetFullPath(caBundlePath, baseDirectory);
        }

        return new ClientOptions
        {
            IssuerUrl = issuerUrl,
            TokenEndpoint = endpoint,
            CaBundlePath = string.IsNullOrEmpty(caBundlePath) ? null : caBundlePath,
        };
    }

    /// <summary>The certificates in <see cref="CaBundlePath"/>, or null to use the system trust store.</summary>
    public X509Certificate2Collection? LoadCaBundle()
    {
        if (CaBundlePath is null)
        {
            return null;
        }

        var roots = new X509Certificate2Collection();
        try
        {
            roots.ImportFromPemFile(CaBundlePath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
        {
            throw new ClientConfigException($"Cannot read the CA bundle {CaBundlePath}: {ex.Message}", ex);
        }

        return roots.Count > 0 ? roots : throw new ClientConfigException($"The CA bundle {CaBundlePath} holds no certificates.");
    }
}
