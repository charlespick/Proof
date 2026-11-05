using System.Text;
using System.Text.Json;
using Proof.Shared;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace Proof.Refresher.Metadata;

/// <summary>A metadata block that cannot be used. The message is for the host's log and never quotes a value.</summary>
public sealed class VmMetadataException(string message) : Exception(message);

/// <summary>
/// A VM's instance metadata: YAML in its Hyper-V notes between two marker lines. Everything
/// outside the markers belongs to the operator and is never read, served or changed.
/// </summary>
public sealed class VmMetadataBlock
{
    public const string BeginMarker = "#proof-metadata-begin";
    public const string EndMarker = "#proof-metadata-end";

    /// <summary>A value that is served until provisioning finishes, then replaced in the notes.</summary>
    public const string SensitiveTag = "!sensitive";

    /// <summary>What a sensitive value becomes: this tag and the time it was cleared. Never served.</summary>
    public const string ClearedTag = "!cleared";

    private const string MetaDataKey = "meta-data";
    private const string UserDataKey = "user-data";
    private const string NetworkDataKey = "network-data";
    private const string ProvisioningKey = "provisioning";
    private const string StatusKey = "status";

    /// <summary>EC2's name for the instance ID, which the provisioning record also uses.</summary>
    private const string InstanceIdKey = "instance-id";

    /// <summary>OpenStack's name for the instance ID, which comes from the BIOS GUID and so can't be set.</summary>
    private const string UuidKey = "uuid";

    private const string HostnameKey = "hostname";
    private const int MaxDepth = 16;

    /// <summary>
    /// EC2's names for meta-data that OpenStack names differently. Served under the old name, each would be ignored by
    /// cloud-init and Cloudbase-Init without a word, so a block that uses one is refused with the name to use instead.
    /// </summary>
    private static readonly Dictionary<string, string> RenamedKeys = new()
    {
        ["local-hostname"] = HostnameKey,
        ["public-keys"] = "public_keys",
    };

    private readonly string notes;
    private readonly int blockStart;
    private readonly int blockEnd;
    private readonly string yaml;
    private readonly YamlMappingNode root;

    private VmMetadataBlock(string notes, int blockStart, int blockEnd)
    {
        this.notes = notes;
        this.blockStart = blockStart;
        this.blockEnd = blockEnd;
        yaml = notes[blockStart..blockEnd];
        root = Load(yaml);
        Validate();
        Provisioning = ReadProvisioning(root);
    }

    /// <summary>One of <see cref="ProvisioningStatus"/>. A block that does not say is pending.</summary>
    public string Provisioning { get; }

    /// <summary>How many values are marked sensitive and have not been cleared.</summary>
    public int SensitiveCount => Scalars(root).Count(IsSensitive);

    /// <summary>The block in <paramref name="notes"/>, or null if there is none.</summary>
    /// <exception cref="VmMetadataException">The markers or the YAML between them are wrong.</exception>
    public static VmMetadataBlock? Find(string? notes)
    {
        if (string.IsNullOrEmpty(notes))
        {
            return null;
        }

        int? start = null, end = null;
        var position = 0;
        while (position < notes.Length)
        {
            // Hyper-V Manager writes CRLF; other tools may write LF. A marker must start its line, which also keeps
            // one inside a block scalar from counting, since a top-level block scalar is indented.
            var newline = notes.IndexOf('\n', position);
            var next = newline < 0 ? notes.Length : newline + 1;
            var line = notes[position..(newline < 0 ? notes.Length : newline)].TrimEnd();
            if (line == BeginMarker)
            {
                if (start is not null)
                {
                    throw new VmMetadataException($"The notes have more than one {BeginMarker} line.");
                }

                start = next;
            }
            else if (line == EndMarker)
            {
                if (start is null || end is not null)
                {
                    throw new VmMetadataException($"{EndMarker} must follow {BeginMarker}, once.");
                }

                end = position;
            }

            position = next;
        }

        return (start, end) switch
        {
            (null, null) => null,
            (not null, not null) => new VmMetadataBlock(notes, start.Value, end.Value),
            _ => throw new VmMetadataException($"The notes have {BeginMarker} with no {EndMarker} after it."),
        };
    }

    /// <summary>What a VM whose notes have no block is served: what Hyper-V knows about it, and nothing from the notes.</summary>
    public static MetadataResponse BasicResponse(string instanceId, string? defaultHostname) =>
        new VmMetadataBlock("", 0, 0).ToResponse(instanceId, defaultHostname) with { Provisioning = ProvisioningStatus.None };

    /// <summary>
    /// The notes of a VM with no block after it reports provisioning finished: the same notes with the least block
    /// that records it added after them, so the host keeps a record of a VM it was not told about.
    /// </summary>
    /// <exception cref="VmMetadataException">The result would not read back as a block. Nothing should be written.</exception>
    public static string AppendFinished(string? notes, string result, string instanceId, DateTimeOffset now)
    {
        notes ??= "";
        // Hyper-V Manager writes CRLF, so that is also what empty notes get.
        var newline = notes.Contains('\n') && !notes.Contains("\r\n", StringComparison.Ordinal) ? "\n" : "\r\n";
        var separator = notes.Length == 0 || notes.EndsWith('\n') ? "" : newline;
        var finished = $"{notes}{separator}{BeginMarker}{newline}{ProvisioningKey}: {Recorded(result, instanceId, Timestamp(now))}{newline}{EndMarker}{newline}";
        return Find(finished)?.Provisioning == result
            ? finished
            : throw new VmMetadataException("Recording the status did not leave the expected YAML, so the notes were not changed.");
    }

    /// <summary>
    /// The response to a guest's read. A sensitive value is served only while provisioning is pending: one an operator
    /// adds to a finished VM stays unserved until they set the status back to pending.
    /// </summary>
    public MetadataResponse ToResponse(string instanceId, string? defaultHostname)
    {
        var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            var hasHostname = false;
            if (Child(root, MetaDataKey) is YamlMappingNode metaData)
            {
                foreach (var (key, value) in metaData.Children.Where(c => IsServed(c.Value)))
                {
                    var name = ((YamlScalarNode)key).Value!;
                    hasHostname |= name == HostnameKey;
                    writer.WritePropertyName(name);
                    WriteJson(writer, value);
                }
            }

            if (!hasHostname && defaultHostname is not null)
            {
                writer.WriteString(HostnameKey, defaultHostname);
            }

            writer.WriteEndObject();
        }

        using var document = JsonDocument.Parse(buffer.ToArray());
        return new MetadataResponse(
            MetadataResponseStatus.Ok,
            instanceId,
            Provisioning,
            document.RootElement.Clone(),
            Served(UserDataKey),
            Served(NetworkDataKey));
    }

    /// <summary>What <paramref name="response"/> serves, by the names in the notes: the instance ID, the meta-data, then the other documents.</summary>
    public static IEnumerable<string> ServedNames(MetadataResponse response)
    {
        yield return UuidKey;
        if (response.MetaData is { ValueKind: JsonValueKind.Object } metaData)
        {
            foreach (var property in metaData.EnumerateObject())
            {
                yield return property.Name;
            }
        }

        if (response.UserData is not null)
        {
            yield return UserDataKey;
        }

        if (response.NetworkData is not null)
        {
            yield return NetworkDataKey;
        }
    }

    /// <summary>A top-level string, if it is there and may be served.</summary>
    private string? Served(string key) => Child(root, key) is YamlScalarNode value && IsServed(value) ? value.Value : null;

    /// <summary>
    /// The notes after provisioning finishes: each sensitive value is replaced, and the status recorded unless the VM
    /// had already finished, in which case the first result stands. Only those spans change, so the operator's
    /// comments and layout survive. The result is parsed again to prove nothing sensitive is left.
    /// </summary>
    /// <exception cref="VmMetadataException">The edit did not come out as it should. Nothing should be written.</exception>
    public string Finish(string result, string instanceId, DateTimeOffset now)
    {
        var at = Timestamp(now);
        var edits = Scalars(root).Where(IsSensitive).Select(s => Span(s, $"{ClearedTag} \"{at}\"")).ToList();

        var status = Provisioning == ProvisioningStatus.Pending ? result : Provisioning;
        if (Provisioning == ProvisioningStatus.Pending)
        {
            var recorded = Recorded(result, instanceId, at);
            if (Child(root, ProvisioningKey) is { } existing)
            {
                edits.Add(Span(existing, recorded));
            }
            else
            {
                var newline = notes.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
                edits.Add((yaml.Length, yaml.Length, $"{ProvisioningKey}: {recorded}{newline}"));
            }
        }

        var text = new StringBuilder(yaml);
        foreach (var (start, end, replacement) in edits.OrderByDescending(e => e.Start))
        {
            text.Remove(start, end - start).Insert(start, replacement);
        }

        var finished = notes[..blockStart] + text + notes[blockEnd..];
        VmMetadataBlock? check;
        try
        {
            check = Find(finished);
        }
        catch (VmMetadataException)
        {
            check = null;
        }

        if (check is null || check.SensitiveCount != 0 || check.Provisioning != status)
        {
            throw new VmMetadataException("Clearing the sensitive values did not leave the expected YAML, so the notes were not changed.");
        }

        return finished;
    }

    private static string Timestamp(DateTimeOffset now) => now.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ");

    private static string Recorded(string result, string instanceId, string at) =>
        $"{{ {StatusKey}: {result}, at: \"{at}\", {InstanceIdKey}: {instanceId} }}";

    /// <summary>
    /// The text span of a node, without trailing whitespace: a block scalar's end mark can lie past its line break,
    /// on the next key, and that break must stay.
    /// </summary>
    private (int Start, int End, string Text) Span(YamlNode node, string replacement)
    {
        var start = checked((int)node.Start.Index);
        var end = node is YamlMappingNode mapping ? MappingEnd(mapping) : checked((int)node.End.Index);
        while (end > start && char.IsWhiteSpace(yaml[end - 1]))
        {
            end--;
        }

        return (start, end, replacement);
    }

    /// <summary>
    /// Where a mapping ends. Its own end mark is where its first event ends, not the mapping. A comment holding a
    /// <c>}</c> could mislead this; <see cref="Finish"/> then finds the result wrong and writes nothing.
    /// </summary>
    private int MappingEnd(YamlMappingNode mapping)
    {
        var last = Scalars(mapping).Select(s => checked((int)s.End.Index)).DefaultIfEmpty(checked((int)mapping.Start.Index)).Max();
        return mapping.Style == YamlDotNet.Core.Events.MappingStyle.Flow ? yaml.IndexOf('}', last) + 1 : last;
    }

    private static YamlMappingNode Load(string yaml)
    {
        var stream = new YamlStream();
        try
        {
            stream.Load(new StringReader(yaml));
        }
        catch (YamlException ex)
        {
            // Only the place: the parser's message can quote the line, which may hold a sensitive value.
            throw new VmMetadataException($"The YAML is not valid, near line {ex.Start.Line} of the block.");
        }

        return stream.Documents.Count switch
        {
            0 => new YamlMappingNode(),
            1 when stream.Documents[0].RootNode is YamlMappingNode mapping => mapping,
            1 => throw new VmMetadataException("The block must be a YAML mapping."),
            _ => throw new VmMetadataException("The block must be one YAML document."),
        };
    }

    private static string ReadProvisioning(YamlMappingNode root)
    {
        var status = Child(root, ProvisioningKey) switch
        {
            null => ProvisioningStatus.Pending,
            YamlScalarNode scalar => scalar.Value,
            YamlMappingNode mapping when Child(mapping, StatusKey) is YamlScalarNode scalar => scalar.Value,
            _ => throw new VmMetadataException($"{ProvisioningKey} must be a status, or a mapping with {StatusKey}."),
        };
        return status is ProvisioningStatus.Pending or ProvisioningStatus.Complete or ProvisioningStatus.Failed
            ? status
            : throw new VmMetadataException($"{ProvisioningKey} must be {ProvisioningStatus.Pending}, {ProvisioningStatus.Complete} or {ProvisioningStatus.Failed}.");
    }

    private void Validate()
    {
        // First, so that nothing below meets a shared node or a tagged key.
        ValidateNode(root, 0);

        foreach (var key in root.Children.Keys)
        {
            if (key is not YamlScalarNode { Value: MetaDataKey or UserDataKey or NetworkDataKey or ProvisioningKey })
            {
                throw new VmMetadataException($"The only top-level keys are {MetaDataKey}, {UserDataKey}, {NetworkDataKey} and {ProvisioningKey}. A misspelled key would be ignored, and a value meant to be sensitive could stay in the notes.");
            }
        }

        if (Child(root, MetaDataKey) is { } metaData)
        {
            if (metaData is not YamlMappingNode metaDataMapping)
            {
                throw new VmMetadataException($"{MetaDataKey} must be a mapping.");
            }

            // The instance ID, under either name.
            foreach (var key in (string[])[UuidKey, InstanceIdKey])
            {
                if (Child(metaDataMapping, key) is not null)
                {
                    throw new VmMetadataException($"{MetaDataKey} must not set {key}: the instance ID, {UuidKey}, comes from the VM's BIOS GUID.");
                }
            }

            foreach (var (old, name) in RenamedKeys)
            {
                if (Child(metaDataMapping, old) is not null)
                {
                    throw new VmMetadataException($"{MetaDataKey} uses EC2's name {old}. The metadata is in OpenStack's format, where it is {name}.");
                }
            }
        }

        if (Child(root, UserDataKey) is { } userData && userData is not YamlScalarNode)
        {
            throw new VmMetadataException($"{UserDataKey} must be a string. Use a | block for several lines.");
        }

        switch (Child(root, NetworkDataKey))
        {
            case null:
                break;
            case YamlScalarNode networkData:
                // A cleared value is a timestamp now, and is never served.
                if (!IsCleared(networkData))
                {
                    ValidateNetworkData(networkData.Value ?? "");
                }

                break;
            default:
                throw new VmMetadataException($"{NetworkDataKey} must be a string holding OpenStack's network_data.json. Use a | block for several lines.");
        }
    }

    /// <summary>
    /// The network document is served as written and only checked here to be a JSON object: cloud-init and
    /// Cloudbase-Init read what is in it, and one that doesn't parse would leave the VM without its network.
    /// </summary>
    private static void ValidateNetworkData(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 64 });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new VmMetadataException($"{NetworkDataKey} must be a JSON object, as network_data.json is.");
            }
        }
        catch (JsonException ex)
        {
            // Only the place: the parser's message can quote the text.
            throw new VmMetadataException($"{NetworkDataKey} is not valid JSON, near line {(ex.LineNumber ?? 0) + 1} of its value.");
        }
    }

    private static void ValidateNode(YamlNode node, int depth)
    {
        if (depth > MaxDepth)
        {
            throw new VmMetadataException($"The block nests deeper than {MaxDepth} levels.");
        }

        // No anchors means no aliases, so the tree has no shared nodes: what is walked is what is written, and a
        // sensitive value cannot also be reached under another name.
        if (!node.Anchor.IsEmpty)
        {
            throw new VmMetadataException("The block must not use YAML anchors or aliases.");
        }

        switch (node)
        {
            case YamlMappingNode mapping:
                RefuseTag(mapping);
                foreach (var (key, value) in mapping.Children)
                {
                    if (key is not YamlScalarNode { Value: { Length: > 0 } name } || !key.Tag.IsEmpty || name.Any(char.IsControl))
                    {
                        throw new VmMetadataException("Keys must be plain text, with no tag.");
                    }

                    ValidateNode(key, depth + 1);
                    ValidateNode(value, depth + 1);
                }

                break;
            case YamlSequenceNode sequence:
                RefuseTag(sequence);
                foreach (var item in sequence.Children)
                {
                    ValidateNode(item, depth + 1);
                }

                break;
            case YamlScalarNode scalar:
                // A misspelled !sensitive must not pass as an ordinary value that stays in the notes for good.
                if (!scalar.Tag.IsEmpty && !IsStandard(scalar.Tag) && !IsSensitive(scalar) && !IsCleared(scalar))
                {
                    throw new VmMetadataException($"Unknown tag on a value. The tags are {SensitiveTag} and {ClearedTag}.");
                }

                break;
        }
    }

    private static void RefuseTag(YamlNode node)
    {
        if (!node.Tag.IsEmpty && !IsStandard(node.Tag))
        {
            throw new VmMetadataException($"{SensitiveTag} goes on each value, not on a mapping or a list.");
        }
    }

    private static bool IsStandard(TagName tag) => tag.Value.StartsWith("tag:yaml.org,2002:", StringComparison.Ordinal);

    private bool IsServed(YamlNode node) =>
        node is not YamlScalarNode scalar
        || (!IsCleared(scalar) && (!IsSensitive(scalar) || Provisioning == ProvisioningStatus.Pending));

    private void WriteJson(Utf8JsonWriter writer, YamlNode node)
    {
        // Everything is a string: the API serves text, so "no" and "012" stay as the operator wrote them.
        switch (node)
        {
            case YamlMappingNode mapping:
                writer.WriteStartObject();
                foreach (var (key, value) in mapping.Children.Where(c => IsServed(c.Value)))
                {
                    writer.WritePropertyName(((YamlScalarNode)key).Value!);
                    WriteJson(writer, value);
                }

                writer.WriteEndObject();
                break;
            case YamlSequenceNode sequence:
                writer.WriteStartArray();
                foreach (var item in sequence.Children.Where(IsServed))
                {
                    WriteJson(writer, item);
                }

                writer.WriteEndArray();
                break;
            case YamlScalarNode scalar:
                writer.WriteStringValue(scalar.Value ?? "");
                break;
        }
    }

    private static YamlNode? Child(YamlMappingNode mapping, string key) =>
        mapping.Children.TryGetValue(new YamlScalarNode(key), out var value) ? value : null;

    private static bool IsSensitive(YamlScalarNode node) => !node.Tag.IsEmpty && node.Tag.Value == SensitiveTag;

    private static bool IsCleared(YamlScalarNode node) => !node.Tag.IsEmpty && node.Tag.Value == ClearedTag;

    private static IEnumerable<YamlScalarNode> Scalars(YamlNode node) => node switch
    {
        YamlScalarNode scalar => [scalar],
        YamlMappingNode mapping => mapping.Children.Values.SelectMany(Scalars),
        YamlSequenceNode sequence => sequence.Children.SelectMany(Scalars),
        _ => [],
    };
}
