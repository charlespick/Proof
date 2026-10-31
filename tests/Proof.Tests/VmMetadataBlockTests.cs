using Proof.Refresher.Metadata;
using Proof.Shared;

namespace Proof.Tests;

public class VmMetadataBlockTests
{
    private const string InstanceId = "i-00000000000000000000000000000001";
    private const string Stamp = "\"2026-10-31T12:00:00Z\"";
    private static readonly DateTimeOffset Now = new(2026, 10, 31, 12, 0, 0, TimeSpan.Zero);

    private static string Notes(string yaml, string newline = "\n") =>
        $"Owner: web team{newline}{VmMetadataBlock.BeginMarker}{newline}{yaml.ReplaceLineEndings(newline)}{VmMetadataBlock.EndMarker}{newline}Do not delete.";

    private static VmMetadataBlock Block(string yaml) => VmMetadataBlock.Find(Notes(yaml))!;

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Just some notes about this VM.\r\nmeta-data: looks like yaml")]
    // Indented, as it would be when quoted inside other text: not a marker.
    [InlineData("  #proof-metadata-begin\n  #proof-metadata-end")]
    public void NotesWithoutMarkersAreNotOptedIn(string? notes) => Assert.Null(VmMetadataBlock.Find(notes));

    [Theory]
    [InlineData("#proof-metadata-begin\nuser-data: x\n")]
    [InlineData("#proof-metadata-end\n#proof-metadata-begin\n")]
    [InlineData("#proof-metadata-begin\n#proof-metadata-end\n#proof-metadata-end\n")]
    [InlineData("#proof-metadata-begin\n#proof-metadata-begin\n#proof-metadata-end\n")]
    public void WrongMarkersAreRefused(string notes) => Assert.Throws<VmMetadataException>(() => VmMetadataBlock.Find(notes));

    [Fact]
    public void EmptyBlockOptsIn()
    {
        var block = VmMetadataBlock.Find($"{VmMetadataBlock.BeginMarker}\r\n{VmMetadataBlock.EndMarker}");
        Assert.Equal(ProvisioningStatus.Pending, block!.Provisioning);
        Assert.Equal(0, block.SensitiveCount);
    }

    [Theory]
    [InlineData("bogus: 1\n")] // A misspelled key must not leave a value behind unnoticed.
    [InlineData("meta-data: text\n")]
    [InlineData("meta-data:\n  instance-id: i-mine\n")] // The instance ID comes from the BIOS GUID only.
    [InlineData("user-data:\n  - a\n")]
    [InlineData("provisioning: done\n")]
    [InlineData("provisioning:\n  status: done\n")]
    [InlineData("user-data: !secret hunter2\n")] // A misspelled tag must not pass as an ordinary value.
    [InlineData("meta-data: !sensitive\n  a: b\n")] // Only values are cleared.
    [InlineData("meta-data:\n  a: &x hunter2\n  b: *x\n")] // A sensitive value could have a second name.
    [InlineData("meta-data:\n  a/b: c\n")]
    [InlineData("meta-data:\n  a: 1\n  a: 2\n")]
    [InlineData("a: 1\n---\nb: 2\n")]
    [InlineData("- a\n")]
    public void BadBlocksAreRefused(string yaml) => Assert.Throws<VmMetadataException>(() => Block(yaml));

    [Fact]
    public void InvalidYamlIsReportedWithoutQuotingIt()
    {
        var ex = Assert.Throws<VmMetadataException>(() => Block("user-data: !sensitive \"hunter2\n"));
        Assert.DoesNotContain("hunter2", ex.Message);
    }

    [Fact]
    public void ServesTreeAsStrings()
    {
        var response = Block("""
            meta-data:
              local-hostname: web01
              answer: 012
              enabled: no
              placement:
                availability-zone: rack-1
              public-keys:
                - ssh-ed25519 AAAA one
            user-data: |
              #cloud-config
              hostname: web01

            """).ToResponse(InstanceId, "ignored");

        Assert.Equal(MetadataResponseStatus.Ok, response.Status);
        Assert.Equal(InstanceId, response.InstanceId);
        Assert.Equal(ProvisioningStatus.Pending, response.Provisioning);
        Assert.Equal("#cloud-config\nhostname: web01\n", response.UserData?.ReplaceLineEndings("\n"));
        var tree = response.MetaData!.Value;
        Assert.Equal("web01", tree.GetProperty("local-hostname").GetString());
        Assert.Equal("012", tree.GetProperty("answer").GetString());
        Assert.Equal("no", tree.GetProperty("enabled").GetString());
        Assert.Equal("rack-1", tree.GetProperty("placement").GetProperty("availability-zone").GetString());
        Assert.Equal("ssh-ed25519 AAAA one", tree.GetProperty("public-keys")[0].GetString());
    }

    [Fact]
    public void HostnameDefaultsToTheOneGiven()
    {
        var response = Block("").ToResponse(InstanceId, "from-vm-name");
        Assert.Equal("from-vm-name", response.MetaData!.Value.GetProperty("local-hostname").GetString());
    }

    [Fact]
    public void SensitiveValuesAreServedWhilePendingWithoutTheTag()
    {
        var block = Block("""
            meta-data:
              admin-pass: !sensitive hunter2
            user-data: !sensitive |
              #cloud-config
              password: hunter3

            """);

        Assert.Equal(2, block.SensitiveCount);
        var response = block.ToResponse(InstanceId, null);
        Assert.Equal("hunter2", response.MetaData!.Value.GetProperty("admin-pass").GetString());
        Assert.Equal("#cloud-config\npassword: hunter3\n", response.UserData?.ReplaceLineEndings("\n"));
    }

    [Theory]
    [InlineData("\n")]
    [InlineData("\r\n")]
    public void FinishClearsOnlySensitiveValuesAndRecordsStatus(string newline)
    {
        var notes = Notes("""
            # Provisioned by the web team.
            meta-data:
              local-hostname: web01   # keep this comment
              admin-pass: !sensitive hunter2  # and this one
              keys:
                - plain
                - !sensitive hunter3
            user-data: !sensitive |
              #cloud-config
              password: hunter4
            provisioning: pending

            """, newline);

        var finished = VmMetadataBlock.Find(notes)!.Finish(ProvisioningStatus.Complete, InstanceId, Now);

        Assert.DoesNotContain("hunter", finished);
        Assert.Equal(Notes($$"""
            # Provisioned by the web team.
            meta-data:
              local-hostname: web01   # keep this comment
              admin-pass: !cleared {{Stamp}}  # and this one
              keys:
                - plain
                - !cleared {{Stamp}}
            user-data: !cleared {{Stamp}}
            provisioning: { status: complete, at: {{Stamp}}, instance-id: {{InstanceId}} }

            """, newline), finished);

        var block = VmMetadataBlock.Find(finished)!;
        Assert.Equal(ProvisioningStatus.Complete, block.Provisioning);
        Assert.Equal(0, block.SensitiveCount);
        var response = block.ToResponse(InstanceId, null);
        Assert.Null(response.UserData);
        Assert.False(response.MetaData!.Value.TryGetProperty("admin-pass", out _));
        Assert.Equal("web01", response.MetaData.Value.GetProperty("local-hostname").GetString());
        Assert.Equal(1, response.MetaData.Value.GetProperty("keys").GetArrayLength());
    }

    [Theory]
    // A block scalar last in the block, with and without trailing blank lines.
    [InlineData("user-data: !sensitive |\n  a\n  b\n", "user-data: !cleared S\nprovisioning: P\n")]
    [InlineData("user-data: !sensitive |\n  a\n\n\n", "user-data: !cleared S\n\n\nprovisioning: P\n")]
    // Keep and strip chomping, folded, then more keys after it.
    [InlineData("user-data: !sensitive |+\n  a\n\nprovisioning: pending\n", "user-data: !cleared S\n\nprovisioning: P\n")]
    [InlineData("meta-data:\n  a: !sensitive >-\n    b\n    c\n  d: e\n", "meta-data:\n  a: !cleared S\n  d: e\nprovisioning: P\n")]
    // Quoted, in a flow mapping, a colon inside.
    [InlineData("meta-data:\n  a: !sensitive 'it''s: b'\n", "meta-data:\n  a: !cleared S\nprovisioning: P\n")]
    [InlineData("meta-data: { a: !sensitive \"b\", c: d }\n", "meta-data: { a: !cleared S, c: d }\nprovisioning: P\n")]
    // An empty value.
    [InlineData("meta-data:\n  a: !sensitive\n  b: c\n", "meta-data:\n  a: !cleared S\n  b: c\nprovisioning: P\n")]
    // A block-mapping status, as an operator might write it, and a flow one.
    [InlineData("provisioning:\n  status: pending\nuser-data: a\n", "provisioning:\n  P\nuser-data: a\n")]
    [InlineData("provisioning: { status: pending }\n", "provisioning: P\n")]
    public void FinishHandlesEveryShapeOfValue(string yaml, string expected)
    {
        var finished = VmMetadataBlock.Find(Notes(yaml))!.Finish(ProvisioningStatus.Failed, InstanceId, Now);
        var recorded = $"{{ status: failed, at: {Stamp}, instance-id: {InstanceId} }}";
        Assert.Equal(Notes(expected.Replace("S", Stamp).Replace("P", recorded)), finished);
        Assert.Equal(ProvisioningStatus.Failed, VmMetadataBlock.Find(finished)!.Provisioning);
    }

    [Fact]
    public void TextOutsideTheBlockIsUntouchedEvenIfItLooksSensitive()
    {
        var notes = $"password: !sensitive not-mine\r\n{VmMetadataBlock.BeginMarker}\r\nuser-data: !sensitive a\r\n{VmMetadataBlock.EndMarker}\r\nmore: !sensitive not-mine-either";
        var finished = VmMetadataBlock.Find(notes)!.Finish(ProvisioningStatus.Complete, InstanceId, Now);
        Assert.StartsWith("password: !sensitive not-mine\r\n", finished);
        Assert.EndsWith("more: !sensitive not-mine-either", finished);
        Assert.Equal(0, VmMetadataBlock.Find(finished)!.SensitiveCount);
    }

    [Fact]
    public void FirstResultStandsButSensitiveValuesAddedLaterAreStillCleared()
    {
        var finished = Block("provisioning: complete\nuser-data: !sensitive a\n").Finish(ProvisioningStatus.Failed, InstanceId, Now);
        Assert.DoesNotContain("failed", finished);
        var block = VmMetadataBlock.Find(finished)!;
        Assert.Equal(ProvisioningStatus.Complete, block.Provisioning);
        Assert.Equal(0, block.SensitiveCount);
    }

    [Fact]
    public void FinishedVmIsNotServedSensitiveValuesUntilResetToPending()
    {
        const string Yaml = "provisioning: complete\nuser-data: !sensitive a\nmeta-data:\n  b: !sensitive c\n";
        var response = Block(Yaml).ToResponse(InstanceId, null);
        Assert.Null(response.UserData);
        Assert.False(response.MetaData!.Value.TryGetProperty("b", out _));

        response = Block(Yaml.Replace("complete", "pending")).ToResponse(InstanceId, null);
        Assert.Equal("a", response.UserData);
        Assert.Equal("c", response.MetaData!.Value.GetProperty("b").GetString());
    }
}
