using Proof.Refresher.Metadata;
using Proof.Shared;

namespace Proof.Tests;

public class VmMetadataBlockTests
{
    private const string InstanceId = "00000000-0000-0000-0000-000000000001";
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
    [InlineData("meta-data:\n  uuid: 1b4e28ba-2fa1-11d2-883f-0016d3cca427\n")] // The instance ID comes from the BIOS GUID only.
    [InlineData("meta-data:\n  instance-id: i-mine\n")]
    [InlineData("user-data:\n  - a\n")]
    [InlineData("network-data:\n  links: []\n")] // A string, served as written.
    [InlineData("network-data: '[]'\n")] // network_data.json is an object.
    [InlineData("network-data: '{\"links\": ['\n")]
    [InlineData("network-data:\n")]
    [InlineData("provisioning: done\n")]
    [InlineData("provisioning:\n  status: done\n")]
    [InlineData("user-data: !secret hunter2\n")] // A misspelled tag must not pass as an ordinary value.
    [InlineData("meta-data: !sensitive\n  a: b\n")] // Only values are cleared.
    [InlineData("meta-data:\n  a: &x hunter2\n  b: *x\n")] // A sensitive value could have a second name.
    [InlineData("meta-data:\n  !!str a: c\n")]
    [InlineData("meta-data:\n  a: 1\n  a: 2\n")]
    [InlineData("a: 1\n---\nb: 2\n")]
    [InlineData("- a\n")]
    public void BadBlocksAreRefused(string yaml) => Assert.Throws<VmMetadataException>(() => Block(yaml));

    [Theory]
    // Served under EC2's names, these would be ignored by cloud-init and Cloudbase-Init without a word.
    [InlineData("local-hostname", "hostname")]
    [InlineData("public-keys", "public_keys")]
    [InlineData("instance-id", "uuid")]
    public void EcTwoNamesAreRefusedWithTheOpenStackName(string old, string name)
    {
        var ex = Assert.Throws<VmMetadataException>(() => Block($"meta-data:\n  {old}: a\n"));
        Assert.Contains(old, ex.Message);
        Assert.Contains(name, ex.Message);
    }

    // Identity.

    private const string Identity = "identity:\n  tenant: acme\n  assigned-id: web01.prod.example.com\n  security-tags: [puppet, ssh-ca]\n";

    [Fact]
    public void ReadsTheIdentity()
    {
        var identity = Block(Identity + "meta-data:\n  hostname: web01\n").Identity!;

        Assert.Equal("acme", identity.Tenant);
        Assert.Equal("web01.prod.example.com", identity.AssignedId);
        Assert.Equal(["puppet", "ssh-ca"], identity.SecurityTags);
    }

    [Fact]
    public void BlockWithoutIdentityHasNone() => Assert.Null(Block("meta-data:\n  hostname: web01\n").Identity);

    [Theory]
    [InlineData("identity:\n  tenant: acme\n  assigned-id: web01\n")]
    [InlineData("identity:\n  tenant: acme\n  assigned-id: web01\n  security-tags: []\n")]
    public void SecurityTagsAreOptional(string yaml) => Assert.Empty(Block(yaml).Identity!.SecurityTags);

    [Fact]
    public void TenantAndAssignedIdAreLowercasedButTagsAreNot()
    {
        var identity = Block("identity:\n  tenant: ACME\n  assigned-id: Web01.Prod.Example.COM\n").Identity!;
        Assert.Equal(("acme", "web01.prod.example.com"), (identity.Tenant, identity.AssignedId));

        Assert.Throws<VmMetadataException>(() => Block("identity:\n  tenant: acme\n  assigned-id: web01\n  security-tags: [Puppet]\n"));
    }

    [Theory]
    [InlineData("identity: acme\n", "must be a mapping")]
    [InlineData("identity:\n  assigned-id: web01\n", "tenant is required")]
    [InlineData("identity:\n  tenant: acme\n", "assigned-id is required")]
    [InlineData("identity:\n  tenant: ''\n  assigned-id: web01\n", "tenant is required")]
    [InlineData("identity:\n  tenant: acme\n  assigned-id: web01\n  security-tag: [puppet]\n", "only keys under identity")]
    [InlineData("identity:\n  tenant: acme\n  assigned-id: web01\n  security-tags: puppet\n", "must be a list")]
    [InlineData("identity:\n  tenant: acme\n  assigned-id: web01\n  security-tags:\n", "must be a list")]
    [InlineData("identity:\n  tenant: acme\n  assigned-id: web01\n  security-tags: [[a]]\n", "must be a list")]
    [InlineData("identity:\n  tenant: [acme]\n  assigned-id: web01\n", "must be a string")]
    [InlineData("identity:\n  tenant: acme:corp\n  assigned-id: web01\n", "tenant must be")]
    [InlineData("identity:\n  tenant: acme\n  assigned-id: web 01\n", "assigned-id must be")]
    [InlineData("identity:\n  tenant: acme\n  assigned-id: web01\n  security-tags: [a, a]\n", "repeats")]
    [InlineData("identity:\n  tenant: acme\n  assigned-id: web01\n  security-tags: ['ssh:ca']\n", "security-tags[0] must be")]
    [InlineData("identity:\n  tenant: !sensitive acme\n  assigned-id: web01\n", "must not use !sensitive")]
    [InlineData("identity:\n  tenant: acme\n  assigned-id: web01\n  security-tags: [!sensitive a]\n", "must not use !sensitive")]
    [InlineData("identity:\n  tenant: acme\n  assigned-id: !cleared \"2026-01-01T00:00:00Z\"\n", "must not use !sensitive")]
    public void BadIdentitiesAreRefusedWithoutQuotingValues(string yaml, string reason)
    {
        var ex = Assert.Throws<VmMetadataException>(() => Block(yaml));
        Assert.Contains(reason, ex.Message);
        Assert.DoesNotContain("acme", ex.Message);
        Assert.DoesNotContain("web01", ex.Message);
    }

    [Fact]
    public void SecurityTagsAreLimitedInNumber()
    {
        var tags = string.Join(", ", Enumerable.Range(0, 17).Select(i => $"t{i}"));
        Assert.Contains("at most 16", Assert.Throws<VmMetadataException>(() => Block($"identity:\n  tenant: a\n  assigned-id: b\n  security-tags: [{tags}]\n")).Message);
    }

    [Fact]
    public void IdentityIsNeverServed()
    {
        var response = Block(Identity + "meta-data:\n  hostname: web01\n").ToResponse(InstanceId, "web01");

        Assert.Equal(new[] { "uuid", "hostname" }, VmMetadataBlock.ServedNames(response));
        Assert.DoesNotContain("acme", response.MetaData!.Value.GetRawText());
    }

    [Fact]
    public void FinishingLeavesTheIdentityInPlace()
    {
        var notes = Notes(Identity + "user-data: !sensitive secret\n");

        var finished = VmMetadataBlock.Find(notes)!.Finish(ProvisioningStatus.Complete, InstanceId, Now);

        Assert.Contains(Identity, finished.ReplaceLineEndings("\n"));
        Assert.Equal(VmMetadataBlock.Find(notes)!.Identity, VmMetadataBlock.Find(finished)!.Identity);
    }

    [Fact]
    public void ServedNamesListTheInstanceIdThenMetaDataThenDocuments()
    {
        var response = Block("meta-data:\n  a: b\nuser-data: x\nnetwork-data: '{}'\n").ToResponse(InstanceId, "web01");
        Assert.Equal(new[] { "uuid", "a", "hostname", "user-data", "network-data" }, VmMetadataBlock.ServedNames(response));
        Assert.Equal(new[] { "uuid", "hostname" }, VmMetadataBlock.ServedNames(Block("").ToResponse(InstanceId, "web01")));
    }

    [Fact]
    public void InvalidYamlIsReportedWithoutQuotingIt()
    {
        var ex = Assert.Throws<VmMetadataException>(() => Block("user-data: !sensitive \"hunter2\n"));
        Assert.DoesNotContain("hunter2", ex.Message);
    }

    [Fact]
    public void InvalidNetworkDataIsReportedWithoutQuotingIt()
    {
        var ex = Assert.Throws<VmMetadataException>(() => Block("network-data: |\n  {\"links\": [],\n   \"hunter2\"}\n"));
        Assert.Contains("line 2", ex.Message);
        Assert.DoesNotContain("hunter2", ex.Message);
    }

    [Fact]
    public void NetworkDataIsServedExactlyAsWritten()
    {
        const string Json = "{\n  \"links\": [ { \"id\": \"eth0\", \"mtu\": 1500 } ],\n  \"networks\": []\n}\n";
        var response = Block($"network-data: |\n{string.Concat(Json.Split('\n').Where(l => l.Length > 0).Select(l => $"  {l}\n"))}").ToResponse(InstanceId, null);
        Assert.Equal(Json, response.NetworkData);
    }

    [Fact]
    public void NetworkDataMayBeSensitiveAndIsThenClearedToo()
    {
        var block = Block("network-data: !sensitive '{\"links\": []}'\n");
        Assert.Equal("{\"links\": []}", block.ToResponse(InstanceId, null).NetworkData);

        var finished = VmMetadataBlock.Find(block.Finish(ProvisioningStatus.Complete, InstanceId, Now))!;
        Assert.Null(finished.ToResponse(InstanceId, null).NetworkData);
        Assert.Equal(0, finished.SensitiveCount);
    }

    [Fact]
    public void KeysNeedNotBePathsAnyMore() =>
        Assert.Equal("c", Block("meta-data:\n  meta:\n    a/b c=d: c\n").ToResponse(InstanceId, null).MetaData!.Value.GetProperty("meta").GetProperty("a/b c=d").GetString());

    [Fact]
    public void ServesTreeAsStrings()
    {
        var response = Block("""
            meta-data:
              hostname: web01
              answer: 012
              enabled: no
              placement:
                availability-zone: rack-1
              public_keys:
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
        Assert.Equal("web01", tree.GetProperty("hostname").GetString());
        Assert.Equal("012", tree.GetProperty("answer").GetString());
        Assert.Equal("no", tree.GetProperty("enabled").GetString());
        Assert.Equal("rack-1", tree.GetProperty("placement").GetProperty("availability-zone").GetString());
        Assert.Equal("ssh-ed25519 AAAA one", tree.GetProperty("public_keys")[0].GetString());
    }

    [Fact]
    public void HostnameDefaultsToTheOneGiven()
    {
        var response = Block("").ToResponse(InstanceId, "from-vm-name");
        Assert.Equal("from-vm-name", response.MetaData!.Value.GetProperty("hostname").GetString());
    }

    [Fact]
    public void SensitiveValuesAreServedWhilePendingWithoutTheTag()
    {
        var block = Block("""
            meta-data:
              admin_pass: !sensitive hunter2
            user-data: !sensitive |
              #cloud-config
              password: hunter3

            """);

        Assert.Equal(2, block.SensitiveCount);
        var response = block.ToResponse(InstanceId, null);
        Assert.Equal("hunter2", response.MetaData!.Value.GetProperty("admin_pass").GetString());
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
              hostname: web01   # keep this comment
              admin_pass: !sensitive hunter2  # and this one
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
              hostname: web01   # keep this comment
              admin_pass: !cleared {{Stamp}}  # and this one
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
        Assert.False(response.MetaData!.Value.TryGetProperty("admin_pass", out _));
        Assert.Equal("web01", response.MetaData.Value.GetProperty("hostname").GetString());
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
