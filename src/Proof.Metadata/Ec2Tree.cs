using System.Text.Json;

namespace Proof.Metadata;

/// <summary>What a path resolves to: text, or the entries of a directory listed the way EC2 lists them.</summary>
public abstract record Ec2Node
{
    public sealed record Leaf(string Text) : Ec2Node;

    /// <param name="KeyName">Set on a key in <c>public-keys</c>, which its parent lists as <c>index=name</c>.</param>
    public sealed record Directory(IReadOnlyList<KeyValuePair<string, Ec2Node>> Entries, string? KeyName = null) : Ec2Node;
}

/// <summary>
/// The EC2 instance metadata tree over a VM's meta-data: a directory lists its children one per line,
/// with a trailing <c>/</c> on those that are directories themselves.
/// </summary>
public static class Ec2Tree
{
    public const string PublicKeys = "public-keys";
    private const string OpenSshKey = "openssh-key";

    /// <summary>Builds the tree of meta-data. <paramref name="instanceId"/> always comes from the host.</summary>
    public static Ec2Node.Directory Build(string instanceId, JsonElement? metaData)
    {
        var entries = new List<KeyValuePair<string, Ec2Node>> { new("instance-id", new Ec2Node.Leaf(instanceId)) };
        if (metaData is { ValueKind: JsonValueKind.Object } tree)
        {
            foreach (var property in tree.EnumerateObject())
            {
                entries.Add(new(property.Name, property.Name == PublicKeys ? BuildPublicKeys(property.Value) : Build(property.Value)));
            }
        }

        return new Ec2Node.Directory(entries);
    }

    /// <summary>The node at <paramref name="segments"/> under <paramref name="root"/>, or null if there is none.</summary>
    public static Ec2Node? Find(Ec2Node root, IEnumerable<string> segments)
    {
        var node = root;
        foreach (var segment in segments)
        {
            if (node is not Ec2Node.Directory directory)
            {
                return null;
            }

            node = directory.Entries.FirstOrDefault(e => e.Key == segment).Value;
            if (node is null)
            {
                return null;
            }
        }

        return node;
    }

    /// <summary>A directory listing, as a caller reads it.</summary>
    public static string List(Ec2Node.Directory directory) =>
        string.Join('\n', directory.Entries.Select(e => e.Value switch
        {
            Ec2Node.Directory { KeyName: { } name } => $"{e.Key}={name}",
            Ec2Node.Directory => $"{e.Key}/",
            _ => e.Key,
        }));

    private static Ec2Node Build(JsonElement value)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                return new Ec2Node.Directory(value.EnumerateObject().Select(p => new KeyValuePair<string, Ec2Node>(p.Name, Build(p.Value))).ToList());
            case JsonValueKind.Array:
                // A list of plain values is one leaf of lines, as EC2 serves security-groups. Anything else is indexed.
                var items = value.EnumerateArray().ToList();
                return items.All(i => i.ValueKind == JsonValueKind.String)
                    ? new Ec2Node.Leaf(string.Join('\n', items.Select(i => i.GetString())))
                    : new Ec2Node.Directory(items.Select((item, index) => new KeyValuePair<string, Ec2Node>(index.ToString(), Build(item))).ToList());
            default:
                return new Ec2Node.Leaf(value.GetString() ?? "");
        }
    }

    /// <summary>
    /// <c>public-keys</c> as an operator writes it, one key, a list or a mapping from name to key, in the shape cloud-init
    /// and Cloudbase-Init walk: <c>public-keys/</c> lists <c>0=name</c>, and <c>public-keys/0/openssh-key</c> is the key.
    /// </summary>
    private static Ec2Node BuildPublicKeys(JsonElement value)
    {
        IEnumerable<(string Name, string Key)> keys = value.ValueKind switch
        {
            JsonValueKind.String => [("key-0", value.GetString() ?? "")],
            JsonValueKind.Array => value.EnumerateArray()
                .Where(k => k.ValueKind == JsonValueKind.String)
                .Select((k, i) => ($"key-{i}", k.GetString() ?? "")),
            JsonValueKind.Object => value.EnumerateObject()
                .Where(p => p.Value.ValueKind == JsonValueKind.String)
                .Select(p => (p.Name, p.Value.GetString() ?? "")),
            _ => [],
        };

        return new Ec2Node.Directory(keys
            .Select((k, i) => new KeyValuePair<string, Ec2Node>(i.ToString(), new Ec2Node.Directory([new(OpenSshKey, new Ec2Node.Leaf(k.Key))], k.Name)))
            .ToList());
    }

}
