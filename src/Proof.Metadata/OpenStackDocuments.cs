using System.Text.Json;

namespace Proof.Metadata;

/// <summary>The documents of OpenStack's metadata service, built from what the host sends.</summary>
public static class OpenStackDocuments
{
    /// <summary>The only version served. See <see cref="MetadataApi"/> for why no dated version is.</summary>
    public const string Latest = "latest";

    public const string MetaData = "meta_data.json";
    public const string NetworkData = "network_data.json";
    public const string UserData = "user_data";

    private const string Uuid = "uuid";
    private const string PublicKeys = "public_keys";

    /// <summary>
    /// <c>meta_data.json</c>: the VM's meta-data with <c>uuid</c>, which always comes from the host, first. Values are
    /// passed through, apart from <c>public_keys</c>.
    /// </summary>
    public static byte[] BuildMetaData(string uuid, JsonElement? metaData)
    {
        var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString(Uuid, uuid);
            if (metaData is { ValueKind: JsonValueKind.Object } tree)
            {
                foreach (var property in tree.EnumerateObject().Where(p => p.Name != Uuid))
                {
                    writer.WritePropertyName(property.Name);
                    if (property.Name == PublicKeys)
                    {
                        WritePublicKeys(writer, property.Value);
                    }
                    else
                    {
                        property.Value.WriteTo(writer);
                    }
                }
            }

            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }

    /// <summary>
    /// <c>public_keys</c> as an operator writes it, one key, a list or a mapping from name to key, as the mapping
    /// OpenStack serves. Cloud-init takes any of the three, but Cloudbase-Init reads only the mapping's values.
    /// </summary>
    private static void WritePublicKeys(Utf8JsonWriter writer, JsonElement value)
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

        writer.WriteStartObject();
        foreach (var (name, key) in keys)
        {
            writer.WriteString(name, key);
        }

        writer.WriteEndObject();
    }
}
