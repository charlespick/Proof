using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using Proof.Shared;

namespace Proof.Refresher.Metadata;

/// <summary>
/// Answers guests' requests from their VMs' notes. The VM ID comes from the hypervisor through the
/// socket, so a guest can only ever reach its own notes, and no text a guest sends is written to them.
/// </summary>
public sealed partial class MetadataRequestHandler(
    IVmNotes vms, IOptions<RefresherOptions> options, TimeProvider time, ILogger<MetadataRequestHandler> logger)
{
    // Read, edit and write of one VM's notes must not overlap. Finishes are rare, so one gate for the host is enough.
    private readonly SemaphoreSlim writeGate = new(1, 1);

    public async Task<MetadataResponse> HandleAsync(Guid vmId, MetadataRequest request, CancellationToken cancellationToken)
    {
        try
        {
            switch (request.Op)
            {
                case MetadataOperations.Get:
                    return await GetAsync(vmId, cancellationToken);
                case MetadataOperations.Finish when ProvisioningStatus.IsFinishResult(request.Result):
                    return await FinishAsync(vmId, request.Result!, cancellationToken);
                default:
                    logger.LogWarning("VM {VmId} sent a request that is not understood.", vmId);
                    return new MetadataResponse(MetadataResponseStatus.Invalid);
            }
        }
        catch (VmMetadataException ex)
        {
            logger.LogWarning("VM {VmId}: its metadata block in the notes cannot be used. {Error}", vmId, ex.Message);
            return new MetadataResponse(MetadataResponseStatus.Invalid);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError("VM {VmId}: could not read or write its settings. {Error}", vmId, ex.Message);
            return new MetadataResponse(MetadataResponseStatus.Unavailable);
        }
    }

    private async Task<MetadataResponse> GetAsync(Guid vmId, CancellationToken cancellationToken)
    {
        // No settings: the caller is not a VM of this host, or it left in the moment since it connected.
        if (await vms.GetVmAsync(vmId, cancellationToken) is not { } settings)
        {
            return new MetadataResponse(MetadataResponseStatus.NotEnrolled);
        }

        if (VmMetadataBlock.Find(settings.Notes) is not { } block)
        {
            return options.Value.UnsetMetadataHandler == UnsetMetadataHandlers.NotFound
                ? new MetadataResponse(MetadataResponseStatus.NotEnrolled)
                : VmMetadataBlock.BasicResponse(InstanceIdFor(settings.BiosGuid), HostnameFrom(settings.Name));
        }

        if (block.Provisioning != ProvisioningStatus.Pending && block.SensitiveCount > 0)
        {
            logger.LogWarning(
                "VM {VmId} ({VmName}): provisioning is {Status}, so {Count} sensitive values are not served. Set provisioning to pending to serve them.",
                vmId, settings.Name, block.Provisioning, block.SensitiveCount);
        }

        return block.ToResponse(InstanceIdFor(settings.BiosGuid), HostnameFrom(settings.Name));
    }

    private async Task<MetadataResponse> FinishAsync(Guid vmId, string result, CancellationToken cancellationToken)
    {
        await writeGate.WaitAsync(cancellationToken);
        try
        {
            if (await vms.GetVmAsync(vmId, cancellationToken) is not { } settings)
            {
                return new MetadataResponse(MetadataResponseStatus.NotEnrolled);
            }

            var instanceId = InstanceIdFor(settings.BiosGuid);
            if (VmMetadataBlock.Find(settings.Notes) is not { } block)
            {
                if (options.Value.UnsetMetadataHandler == UnsetMetadataHandlers.NotFound)
                {
                    return new MetadataResponse(MetadataResponseStatus.NotEnrolled);
                }

                await vms.WriteNotesAsync(vmId, VmMetadataBlock.AppendFinished(settings.Notes, result, instanceId, time.GetUtcNow()), cancellationToken);
                logger.LogInformation("VM {VmId} ({VmName}) reported provisioning {Result} with no block in its notes; added one to record it.", vmId, settings.Name, result);
                return new MetadataResponse(MetadataResponseStatus.Ok, instanceId, result);
            }

            var sensitive = block.SensitiveCount;
            if (block.Provisioning == ProvisioningStatus.Pending || sensitive > 0)
            {
                await vms.WriteNotesAsync(vmId, block.Finish(result, instanceId, time.GetUtcNow()), cancellationToken);
                logger.LogInformation(
                    "VM {VmId} ({VmName}) reported provisioning {Result}; cleared {Count} sensitive values.", vmId, settings.Name, result, sensitive);
            }

            return new MetadataResponse(
                MetadataResponseStatus.Ok, instanceId, block.Provisioning == ProvisioningStatus.Pending ? result : block.Provisioning);
        }
        finally
        {
            writeGate.Release();
        }
    }

    /// <summary>
    /// The instance ID is the VM's BIOS GUID, in the form the guest reads from SMBIOS (<c>/sys/class/dmi/id/product_uuid</c>
    /// on Linux): cloud-init reuses its cached data on a later boot only if the two match. A copy that keeps the GUID
    /// is the same instance; a copy given a new one is provisioned as a new instance.
    /// </summary>
    public static string InstanceIdFor(Guid biosGuid) => biosGuid.ToString("D");

    /// <summary>The VM's name as its default hostname, if it can be one.</summary>
    public static string? HostnameFrom(string name) => HostnamePattern().IsMatch(name) ? name : null;

    [GeneratedRegex("^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")]
    private static partial Regex HostnamePattern();
}
