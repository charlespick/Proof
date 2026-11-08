using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

namespace Proof.Shared;

/// <summary>
/// What a VM is for, from the <c>identity:</c> block in its notes: a tenant, an ID the operator assigns, and security
/// tags. The host signs it into the host token and the issuer copies it into issued JWTs and their subject. These are
/// assertions by whoever can write the VM's notes, never authorization: consumers decide what they allow.
/// </summary>
/// <remarks>
/// The values go into a subject separated by <c>:</c>, so each is limited to lowercase letters, digits, <c>.</c>,
/// <c>-</c> and <c>_</c>, and starts with a letter or digit. An instance only ever holds canonical values: the
/// refresher lowercases the tenant and assigned ID before it creates one, and the issuer refuses anything else.
/// </remarks>
public sealed partial class VmIdentity : IEquatable<VmIdentity>
{
    public const int MaxTenantLength = 63;
    public const int MaxAssignedIdLength = 253;
    public const int MaxSecurityTags = 16;
    public const int MaxSecurityTagLength = 63;

    private VmIdentity(string tenant, string assignedId, IReadOnlyList<string> securityTags)
    {
        Tenant = tenant;
        AssignedId = assignedId;
        SecurityTags = securityTags;
    }

    public string Tenant { get; }

    /// <summary>Whatever label the operator chooses: a hostname, an FQDN or anything else that fits the rule.</summary>
    public string AssignedId { get; }

    /// <summary>In the order the notes list them, with no duplicates. Possibly empty.</summary>
    public IReadOnlyList<string> SecurityTags { get; }

    /// <summary>
    /// An identity from canonical values, or false with the reason they are not. The reason names the field and the
    /// rule in the notes' terms, never a value, so it can go to a log.
    /// </summary>
    public static bool TryCreate(
        string? tenant,
        string? assignedId,
        IReadOnlyList<string>? securityTags,
        [NotNullWhen(true)] out VmIdentity? identity,
        [NotNullWhen(false)] out string? problem)
    {
        identity = null;
        securityTags ??= [];
        problem = Check(tenant, "tenant", MaxTenantLength, TenantPattern())
            ?? Check(assignedId, "assigned-id", MaxAssignedIdLength, AssignedIdPattern())
            ?? CheckTags(securityTags);
        if (problem is not null)
        {
            return false;
        }

        identity = new VmIdentity(tenant!, assignedId!, securityTags.ToArray());
        return true;
    }

    private static string? Check(string? value, string field, int maxLength, Regex pattern) =>
        string.IsNullOrEmpty(value) ? $"{field} is required."
        : pattern.IsMatch(value) ? null
        : $"{field} must be 1 to {maxLength} lowercase letters, digits, '.', '-' or '_', starting with a letter or digit.";

    private static string? CheckTags(IReadOnlyList<string> tags)
    {
        if (tags.Count > MaxSecurityTags)
        {
            return $"security-tags may list at most {MaxSecurityTags} tags.";
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < tags.Count; i++)
        {
            if (!SecurityTagPattern().IsMatch(tags[i] ?? ""))
            {
                return $"security-tags[{i}] must be 1 to {MaxSecurityTagLength} lowercase letters, digits, '.', '-' or '_', starting with a letter or digit.";
            }

            if (!seen.Add(tags[i]))
            {
                return $"security-tags[{i}] repeats an earlier tag.";
            }
        }

        return null;
    }

    // \z rather than $, which would also match before a final line break.
    [GeneratedRegex(@"^[a-z0-9][a-z0-9._-]{0,62}\z")]
    private static partial Regex TenantPattern();

    [GeneratedRegex(@"^[a-z0-9][a-z0-9._-]{0,252}\z")]
    private static partial Regex AssignedIdPattern();

    [GeneratedRegex(@"^[a-z0-9][a-z0-9._-]{0,62}\z")]
    private static partial Regex SecurityTagPattern();

    public bool Equals(VmIdentity? other) =>
        other is not null
        && Tenant == other.Tenant
        && AssignedId == other.AssignedId
        && SecurityTags.SequenceEqual(other.SecurityTags, StringComparer.Ordinal);

    public override bool Equals(object? obj) => Equals(obj as VmIdentity);

    public override int GetHashCode() => HashCode.Combine(Tenant, AssignedId, SecurityTags.Count);

    public override string ToString() =>
        $"tenant {Tenant}, assigned ID {AssignedId}, security tags [{string.Join(", ", SecurityTags)}]";
}
