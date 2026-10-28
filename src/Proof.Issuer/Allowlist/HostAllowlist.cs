using Microsoft.IdentityModel.Tokens;

namespace Proof.Issuer.Allowlist;

public enum HostKeyStatus
{
    Active,
    Retired,
}

/// <summary>One host public key from the allowlist.</summary>
/// <param name="NotAfter">Exclusive end of the key's validity, or null for no end.</param>
public sealed record AllowlistKey(
    string Kid,
    string Host,
    string? Cluster,
    HostKeyStatus Status,
    DateTimeOffset? NotAfter,
    ECDsaSecurityKey Key)
{
    /// <summary>
    /// An active key is usable until <see cref="NotAfter"/>, if set. A retired key always has
    /// <see cref="NotAfter"/> (the parser requires it) and is usable until then.
    /// </summary>
    public bool IsUsableAt(DateTimeOffset now) => NotAfter is null || now < NotAfter;
}

/// <summary>An immutable, validated allowlist. The monitor swaps whole instances, never edits one.</summary>
public sealed class HostAllowlist(IReadOnlyDictionary<string, AllowlistKey> keys, string sha256)
{
    public IReadOnlyDictionary<string, AllowlistKey> Keys { get; } = keys;

    /// <summary>Hex SHA-256 of the file this list was parsed from, for logs.</summary>
    public string Sha256 { get; } = sha256;

    public int HostCount => Keys.Values.Select(k => k.Host).Distinct(StringComparer.Ordinal).Count();

    /// <summary>Finds <paramref name="kid"/> only among keys already on the list and usable at <paramref name="now"/>.</summary>
    public bool TryGetUsableKey(string? kid, DateTimeOffset now, out AllowlistKey key)
    {
        if (kid is not null && Keys.TryGetValue(kid, out var found) && found.IsUsableAt(now))
        {
            key = found;
            return true;
        }

        key = null!;
        return false;
    }
}
