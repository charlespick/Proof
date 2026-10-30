using System.Globalization;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Proof.Shared;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Proof.Issuer.Allowlist;

public sealed class AllowlistException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// Parses and validates the host allowlist (Design.md 7.2). Any problem fails the whole file, so the monitor
/// keeps the previous list. Unknown fields are errors, so a typo cannot silently drop a check.
/// </summary>
public static class AllowlistParser
{
    public const int MaxFileBytes = 1024 * 1024;

    private static readonly IDeserializer Deserializer = new DeserializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .Build();

    private static readonly HashSet<string> JwkMembers = ["kty", "crv", "x", "y"];

    public static HostAllowlist Parse(byte[] content)
    {
        if (content.Length > MaxFileBytes)
        {
            throw new AllowlistException($"The allowlist is larger than {MaxFileBytes} bytes.");
        }

        Document? doc;
        try
        {
            doc = Deserializer.Deserialize<Document?>(new StringReader(System.Text.Encoding.UTF8.GetString(content)));
        }
        catch (YamlException ex)
        {
            throw new AllowlistException($"The allowlist is not valid YAML for this schema: {ex.Message}", ex);
        }

        if (doc is null)
        {
            throw new AllowlistException("The allowlist is empty.");
        }

        if (doc.Version != 1)
        {
            throw new AllowlistException($"Unsupported allowlist version '{doc.Version}'; expected 1.");
        }

        if (doc.Hosts is null || doc.Hosts.Count == 0)
        {
            throw new AllowlistException("The allowlist has no hosts.");
        }

        var keys = new Dictionary<string, AllowlistKey>(StringComparer.Ordinal);
        var hosts = new HashSet<string>(StringComparer.Ordinal);

        for (var h = 0; h < doc.Hosts.Count; h++)
        {
            var entry = doc.Hosts[h];
            var where = $"hosts[{h}]";

            if (string.IsNullOrWhiteSpace(entry.Host))
            {
                throw new AllowlistException($"{where}.host is required.");
            }

            // Names go into issued subjects, so they keep to the refresher's rule and never hold a '/' or ':'.
            if (!ProofNames.IsValid(entry.Host))
            {
                throw new AllowlistException($"{where}.host '{entry.Host}' must be 1 to 253 letters, digits, '.', '-' or '_', starting with a letter or digit.");
            }

            if (!hosts.Add(entry.Host))
            {
                throw new AllowlistException($"Host '{entry.Host}' is listed more than once.");
            }

            if (entry.Cluster is not null && string.IsNullOrWhiteSpace(entry.Cluster))
            {
                throw new AllowlistException($"{where}.cluster is empty; omit it instead.");
            }

            if (entry.Cluster is not null && !ProofNames.IsValid(entry.Cluster))
            {
                throw new AllowlistException($"{where}.cluster '{entry.Cluster}' must be 1 to 253 letters, digits, '.', '-' or '_', starting with a letter or digit.");
            }

            if (entry.Keys is null || entry.Keys.Count == 0)
            {
                throw new AllowlistException($"Host '{entry.Host}' has no keys; remove the host instead.");
            }

            for (var k = 0; k < entry.Keys.Count; k++)
            {
                var key = ParseKey(entry.Keys[k], entry.Host, entry.Cluster, $"{where}.keys[{k}]");
                if (!keys.TryAdd(key.Kid, key))
                {
                    throw new AllowlistException($"Key '{key.Kid}' is listed more than once.");
                }
            }
        }

        return new HostAllowlist(keys, Convert.ToHexStringLower(SHA256.HashData(content)));
    }

    private static AllowlistKey ParseKey(KeyEntry entry, string host, string? cluster, string where)
    {
        if (string.IsNullOrWhiteSpace(entry.Kid))
        {
            throw new AllowlistException($"{where}.kid is required.");
        }

        var status = entry.Status switch
        {
            "active" => HostKeyStatus.Active,
            "retired" => HostKeyStatus.Retired,
            _ => throw new AllowlistException($"{where}.status must be 'active' or 'retired'."),
        };

        DateTimeOffset? notAfter = null;
        if (entry.NotAfter is not null)
        {
            if (!DateOnly.TryParseExact(entry.NotAfter, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var date))
            {
                throw new AllowlistException($"{where}.not_after must be a date in the form YYYY-MM-DD.");
            }

            // The key is accepted through the whole of that UTC day.
            notAfter = new DateTimeOffset(date.AddDays(1).ToDateTime(TimeOnly.MinValue), TimeSpan.Zero);
        }
        else if (status == HostKeyStatus.Retired)
        {
            throw new AllowlistException($"{where} is retired and needs not_after; remove the key to stop trusting it now.");
        }

        var jwk = ParseJwk(entry.Jwk, where);
        var computedKid = ProofKeys.ComputeKid(jwk);
        if (!string.Equals(computedKid, entry.Kid, StringComparison.Ordinal))
        {
            throw new AllowlistException($"{where}.kid does not match the JWK thumbprint of its key ({computedKid}).");
        }

        return new AllowlistKey(entry.Kid, host, cluster, status, notAfter, CreateSecurityKey(jwk, where));
    }

    private static JsonWebKey ParseJwk(Dictionary<string, string>? members, string where)
    {
        if (members is null)
        {
            throw new AllowlistException($"{where}.jwk is required.");
        }

        if (members.ContainsKey("d"))
        {
            throw new AllowlistException($"{where}.jwk contains a private key. Only the public key may leave the host.");
        }

        var unknown = members.Keys.FirstOrDefault(m => !JwkMembers.Contains(m));
        if (unknown is not null)
        {
            throw new AllowlistException($"{where}.jwk has unexpected member '{unknown}'; only kty, crv, x and y are allowed.");
        }

        if (members.GetValueOrDefault("kty") != JsonWebAlgorithmsKeyTypes.EllipticCurve
            || members.GetValueOrDefault("crv") != JsonWebKeyECTypes.P256)
        {
            throw new AllowlistException($"{where}.jwk must be kty EC with crv P-256.");
        }

        if (string.IsNullOrEmpty(members.GetValueOrDefault("x")) || string.IsNullOrEmpty(members.GetValueOrDefault("y")))
        {
            throw new AllowlistException($"{where}.jwk needs x and y.");
        }

        return new JsonWebKey
        {
            Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve,
            Crv = JsonWebKeyECTypes.P256,
            X = members.GetValueOrDefault("x"),
            Y = members.GetValueOrDefault("y"),
        };
    }

    private static ECDsaSecurityKey CreateSecurityKey(JsonWebKey jwk, string where)
    {
        try
        {
            // Importing with an explicit curve makes the platform check that the point lies on P-256.
            var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = Base64UrlEncoder.DecodeBytes(jwk.X), Y = Base64UrlEncoder.DecodeBytes(jwk.Y) },
            });
            return new ECDsaSecurityKey(ecdsa) { KeyId = ProofKeys.ComputeKid(jwk) };
        }
        // Windows CNG reports a point off the curve as PlatformNotSupportedException; Linux OpenSSL as CryptographicException.
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException or PlatformNotSupportedException)
        {
            throw new AllowlistException($"{where}.jwk is not a valid P-256 public key.", ex);
        }
    }

    private sealed class Document
    {
        public int? Version { get; set; }
        public List<HostEntry>? Hosts { get; set; }
    }

    private sealed class HostEntry
    {
        public string? Host { get; set; }
        public string? Cluster { get; set; }
        public List<KeyEntry>? Keys { get; set; }
    }

    private sealed class KeyEntry
    {
        public string? Kid { get; set; }
        public string? Status { get; set; }
        public string? NotAfter { get; set; }
        public Dictionary<string, string>? Jwk { get; set; }
    }
}
