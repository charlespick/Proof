using System.Text;
using Proof.Client;
using Proof.Shared;

namespace Proof.Tests;

/// <summary>Linux KVP pool files in the layout hv_kvp_daemon writes. The parser and the file reads run on any OS.</summary>
public sealed class KvpPoolTests : IDisposable
{
    private readonly string directory = Directory.CreateTempSubdirectory("proof-kvp-tests-").FullName;

    public void Dispose() => Directory.Delete(directory, recursive: true);

    /// <summary>Records as the daemon stores them: a NUL-padded 512-byte key, then a NUL-padded 2048-byte value.</summary>
    private static byte[] Pool(params (string Key, string Value)[] records)
    {
        var data = new byte[records.Length * LinuxKvpPool.RecordSize];
        for (var i = 0; i < records.Length; i++)
        {
            var offset = i * LinuxKvpPool.RecordSize;
            Encoding.UTF8.GetBytes(records[i].Key).CopyTo(data, offset);
            Encoding.UTF8.GetBytes(records[i].Value).CopyTo(data, offset + LinuxKvpPool.KeySize);
        }

        return data;
    }

    private void WritePool(int pool, byte[] data) => File.WriteAllBytes(Path.Combine(directory, $".kvp_pool_{pool}"), data);

    [Fact]
    public void ParsesRecords()
    {
        var records = LinuxKvpPool.ParseRecords(Pool(("first", "one"), ("second", "two")));

        Assert.Equal([new("first", "one"), new("second", "two")], records);
    }

    [Fact]
    public void IgnoresEmptyKeysAndATrailingPartialRecord()
    {
        var data = Pool(("", "ignored"), ("kept", "yes"), ("cut", "short"));

        var records = LinuxKvpPool.ParseRecords(data.AsSpan(0, data.Length - 1));

        Assert.Equal([new("kept", "yes")], records);
    }

    [Fact]
    public void DecodesUtf8()
    {
        var records = LinuxKvpPool.ParseRecords(Pool(("VirtualMachineName", "wéb-01")));

        Assert.Equal("wéb-01", Assert.Single(records).Value);
    }

    [Fact]
    public void ReadsTheLongestValueTheHostAccepts()
    {
        var value = new string('a', KvpLimits.MaxValueLength);
        WritePool(0, Pool((KvpKeys.Token, value)));

        Assert.Equal(value, new LinuxKvpPool(directory).ReadExternal(KvpKeys.Token));
    }

    [Fact]
    public void ReadsTheTokenFromTheExternalPool()
    {
        WritePool(0, Pool(("other", "x"), (KvpKeys.Token, "header.payload.signature")));

        var pool = new LinuxKvpPool(directory);

        Assert.Equal("header.payload.signature", pool.ReadExternal(KvpKeys.Token));
        Assert.Null(pool.ReadExternal("missing"));
        Assert.Equal(Path.Combine(directory, ".kvp_pool_0"), pool.Source);
    }

    [Fact]
    public void AnEmptyPoolHasNoToken()
    {
        WritePool(0, []);

        Assert.Null(new LinuxKvpPool(directory).ReadExternal(KvpKeys.Token));
    }

    [Fact]
    public void ReadsGuestParametersFromPool3()
    {
        WritePool(0, []);
        WritePool(3, Pool(
            (GuestParameterNames.VirtualMachineId, "11111111-2222-3333-4444-555555555555"),
            (GuestParameterNames.PhysicalHostName, "HV-HOST-01")));

        var parameters = new LinuxKvpPool(directory).ReadGuestParameters();

        Assert.Equal("HV-HOST-01", parameters[GuestParameterNames.PhysicalHostName]);
        Assert.Equal("11111111-2222-3333-4444-555555555555", parameters[GuestParameterNames.VirtualMachineId]);
    }

    [Fact]
    public void MissingGuestParametersAreEmpty()
    {
        Assert.Empty(new LinuxKvpPool(Path.Combine(directory, "absent")).ReadGuestParameters());
    }

    [Fact]
    public void AMissingDirectoryIsUnavailable()
    {
        var ex = Assert.Throws<KvpUnavailableException>(() => new LinuxKvpPool(Path.Combine(directory, "absent")).ReadExternal(KvpKeys.Token));

        Assert.Contains("hv_kvp_daemon", ex.Message);
    }

    [Fact]
    public void AMissingPoolFileIsUnavailable()
    {
        var ex = Assert.Throws<KvpUnavailableException>(() => new LinuxKvpPool(directory).ReadExternal(KvpKeys.Token));

        Assert.Contains(".kvp_pool_0", ex.Message);
    }
}
