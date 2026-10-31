using Proof.Refresher;

namespace Proof.Tests.Support;

/// <summary>In-memory VM settings.</summary>
public sealed class FakeVmNotes : IVmNotes
{
    private readonly Dictionary<Guid, VmSettings> vms = [];

    public int Writes { get; private set; }

    public bool FailWrites { get; set; }

    public Guid Add(string name, Guid biosGuid, string? notes)
    {
        var id = Guid.NewGuid();
        vms[id] = new VmSettings(id, name, biosGuid, notes);
        return id;
    }

    public string? Notes(Guid id) => vms[id].Notes;

    public void SetBiosGuid(Guid id, Guid biosGuid) => vms[id] = vms[id] with { BiosGuid = biosGuid };

    public Task<VmSettings?> GetVmAsync(Guid vmId, CancellationToken cancellationToken) => Task.FromResult(vms.GetValueOrDefault(vmId));

    public Task<IReadOnlyList<VmSettings>> GetVmsAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<VmSettings>>(vms.Values.ToList());

    public Task WriteNotesAsync(Guid vmId, string notes, CancellationToken cancellationToken)
    {
        if (FailWrites)
        {
            throw new KvpWriteException("ModifySystemSettings failed with error 32768: test failure", 32768);
        }

        Writes++;
        vms[vmId] = vms[vmId] with { Notes = notes };
        return Task.CompletedTask;
    }

    public Task WriteBiosGuidAsync(Guid vmId, Guid biosGuid, CancellationToken cancellationToken)
    {
        SetBiosGuid(vmId, biosGuid);
        return Task.CompletedTask;
    }
}
