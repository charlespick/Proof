using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Proof.Shared;

namespace Proof.Client;

/// <summary>
/// What a host token says, read without verifying it. Only the issuer holds the host allowlist, so the client cannot
/// verify host tokens; this is for status output and for explaining a refusal, never for trusting anything.
/// </summary>
/// <param name="SecurityTags">The tags, or null if the token has no array of them.</param>
public sealed record HostTokenInfo(
    int Length,
    string? Type,
    string? Kid,
    string Host,
    string? Tenant,
    string? AssignedId,
    IReadOnlyList<string>? SecurityTags,
    string Audience,
    string VmId,
    string? VmName,
    string? Jti,
    DateTimeOffset IssuedAt,
    DateTimeOffset NotBefore,
    DateTimeOffset Expires)
{
    /// <summary>Signed longer ago than this, a token has missed a renewal.</summary>
    private static readonly TimeSpan StaleAfter = HostTokenPolicy.RefreshInterval + TimeSpan.FromMinutes(1);

    /// <summary>Reads the header and claims. JOSE parsing is Microsoft.IdentityModel's.</summary>
    /// <exception cref="FormatException">Not a compact JWS.</exception>
    public static HostTokenInfo Read(string token)
    {
        if (token.Length > HostTokenPolicy.MaxEncodedLength)
        {
            throw new FormatException($"It is {token.Length} characters, over the {HostTokenPolicy.MaxEncodedLength}-character limit.");
        }

        JsonWebToken jwt;
        try
        {
            jwt = new JsonWebToken(token);
        }
        catch (Exception ex) when (ex is ArgumentException or SecurityTokenMalformedException)
        {
            throw new FormatException("It is not a well-formed JWT.", ex);
        }

        static DateTimeOffset Time(DateTime t) => t == DateTime.MinValue ? DateTimeOffset.MinValue : new DateTimeOffset(t, TimeSpan.Zero);
        static string? Claim(JsonWebToken jwt, string name) => jwt.TryGetPayloadValue<string>(name, out var value) ? value : null;

        return new HostTokenInfo(
            token.Length,
            jwt.Typ,
            jwt.Kid,
            jwt.Issuer,
            Claim(jwt, ProofClaimNames.Tenant),
            Claim(jwt, ProofClaimNames.AssignedId),
            Tags(jwt),
            jwt.Audiences.FirstOrDefault() ?? "",
            jwt.Subject,
            Claim(jwt, ProofClaimNames.VmName),
            jwt.Id,
            Time(jwt.IssuedAt),
            Time(jwt.ValidFrom),
            Time(jwt.ValidTo));
    }

    /// <summary>The security tags, from the payload itself: an array claim of strings, as the refresher writes it.</summary>
    private static string[]? Tags(JsonWebToken jwt)
    {
        try
        {
            using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(jwt.EncodedPayload));
            return payload.RootElement.TryGetProperty(ProofClaimNames.SecurityTags, out var tags)
                && tags.ValueKind == JsonValueKind.Array
                && tags.EnumerateArray().All(t => t.ValueKind == JsonValueKind.String)
                    ? tags.EnumerateArray().Select(t => t.GetString()!).ToArray()
                    : null;
        }
        catch (Exception ex) when (ex is JsonException or FormatException or ArgumentException)
        {
            return null;
        }
    }

    public bool IsExpired(DateTimeOffset now) => now >= Expires;

    /// <summary>The identity the token carries, or null if its claims are missing or not ones the issuer accepts.</summary>
    public VmIdentity? Identity =>
        SecurityTags is not null && VmIdentity.TryCreate(Tenant, AssignedId, SecurityTags, out var identity, out _) ? identity : null;

    /// <summary>The <c>sub</c> the issuer will give this VM, or null if it will refuse the token's identity.</summary>
    public string? Subject => Identity is { } identity ? ProofSubjects.For(identity, VmId) : null;

    /// <summary>Reasons the issuer will refuse this token, as far as the VM can tell.</summary>
    public IEnumerable<string> Problems(DateTimeOffset now, string? issuerUrl)
    {
        if (Type != ProofTokenTypes.HostToken)
        {
            yield return $"It is not a Proof host token (typ {Type ?? "missing"}).";
        }

        if (Tenant is null || AssignedId is null)
        {
            yield return $"It has no {ProofClaimNames.Tenant} or {ProofClaimNames.AssignedId}, which the issuer requires. "
                + $"proof-refresher on {Display.Name(Host)} may be older than the issuer.";
        }
        else if (Identity is null)
        {
            yield return "Its identity claims break the rules the issuer holds them to. "
                + $"proof-refresher on {Display.Name(Host)} may be older or newer than the issuer.";
        }

        if (Expires == DateTimeOffset.MinValue)
        {
            yield return "It has no expiry.";
        }
        else if (IsExpired(now))
        {
            yield return $"It expired at {Display.Time(Expires)}, {Display.Duration(now - Expires)} ago. The host renews it every "
                + $"{Display.Duration(HostTokenPolicy.RefreshInterval)}, so proof-refresher on {Display.Name(Host)} may be down, or this VM's clock is wrong.";
        }

        if (NotBefore > now + HostTokenPolicy.ClockSkew)
        {
            yield return $"It is not valid until {Display.Time(NotBefore)}: this VM's clock is {Display.Duration(NotBefore - now)} behind the host's. Check NTP.";
        }

        if (issuerUrl is not null && Audience != issuerUrl)
        {
            yield return $"Its audience is {Display.Name(Audience)}, but this VM is configured for issuer {issuerUrl}. "
                + "The host's Proof:IssuerUrl and this VM's IssuerUrl must be the same.";
        }
    }

    /// <summary>Signs of trouble that do not stop an exchange yet.</summary>
    public IEnumerable<string> Warnings(DateTimeOffset now)
    {
        if (!IsExpired(now) && IssuedAt != DateTimeOffset.MinValue && now - IssuedAt > StaleAfter)
        {
            yield return $"It was signed {Display.Duration(now - IssuedAt)} ago and should have been renewed: proof-refresher on {Display.Name(Host)} "
                + "may not be running, or this VM's clock is wrong.";
        }
    }
}

/// <summary>Formatting for the client's messages.</summary>
internal static class Display
{
    public static string Time(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");

    public static string Duration(TimeSpan d)
    {
        d = d.Duration();
        return d.TotalDays >= 1 ? $"{(int)d.TotalDays}d {d.Hours}h"
            : d.TotalHours >= 1 ? $"{(int)d.TotalHours}h {d.Minutes}m"
            : d.TotalMinutes >= 1 ? (d.Seconds == 0 ? $"{(int)d.TotalMinutes}m" : $"{(int)d.TotalMinutes}m {d.Seconds}s")
            : $"{(int)d.TotalSeconds}s";
    }

    public static string Name(string? value) => string.IsNullOrEmpty(value) ? "(none)" : value;
}
