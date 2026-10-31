<#
.SYNOPSIS
  Checks instance metadata's use of Hyper-V settings against real Hyper-V: reading and rewriting a VM's notes, reading
  its BIOS GUID and giving it a new one.

.DESCRIPTION
  Needs an elevated session on a machine with Hyper-V. It creates one VM with no disk, never starts it, and removes it
  afterwards. It touches no other VM. It does not exercise a guest: see "Checking on a real VM" in README.md.

.EXAMPLE
  dotnet publish src/Proof.Refresher -c Release -r win-x64 -o publish\refresher
  installer\Test-VmNotes.ps1 -Refresher publish\refresher\proof-refresher.exe
#>
param(
    [Parameter(Mandatory)] [string] $Refresher
)

$ErrorActionPreference = 'Stop'
$Refresher = (Resolve-Path $Refresher).Path
$vmName = "proof-notes-test-$PID"

function Check([bool] $condition, [string] $what) {
    if (-not $condition) { throw "FAILED: $what" }
    Write-Host "ok: $what"
}

function Invoke-Refresher {
    $output = & $Refresher @args 2>&1 | Out-String
    [pscustomobject]@{ Exit = $LASTEXITCODE; Output = $output }
}

function Get-Settings([guid] $vmId) {
    Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_VirtualSystemSettingData -Filter "VirtualSystemIdentifier='$vmId' AND VirtualSystemType='Microsoft:Hyper-V:System:Realized'"
}

# Through CIM, because Get-VM can show notes this session already saw, not what another process has since written.
function Get-Notes([guid] $vmId) { (Get-Settings $vmId).Notes -join "`r`n" }

function Get-BiosGuid([guid] $vmId) { ([guid](Get-Settings $vmId).BIOSGUID).ToString('N') }

$vm = New-VM -Name $vmName -Generation 2 -NoVHD
try {
    $id = $vm.Id
    $instanceId = "i-$(Get-BiosGuid $id)"

    $result = Invoke-Refresher metadata show --vm $vmName
    Check ($result.Exit -eq 0 -and $result.Output -match 'No metadata block') 'a VM with empty notes has no block'
    Check ($result.Output -match [regex]::Escape($instanceId)) "its instance ID is its BIOS GUID ($instanceId)"

    $outside = "Owned by the web team.`r`nDo not delete."
    Set-VM -VM $vm -Notes $outside
    Check ((Invoke-Refresher metadata show --vm $vmName).Output -match 'No metadata block') 'ordinary notes are not a block'

    # CRLF, as Hyper-V Manager writes.
    $notes = @(
        'Owned by the web team.'
        '#proof-metadata-begin'
        '# Written by hand, with <markup> & "quotes" and é.'
        'meta-data:'
        '  local-hostname: web01'
        '  admin-pass: !sensitive hunter2'
        'user-data: !sensitive |'
        '  #cloud-config'
        '  password: hunter3'
        'provisioning: pending'
        '#proof-metadata-end'
        'Do not delete.'
    ) -join "`r`n"
    Set-VM -VM $vm -Notes $notes

    $result = Invoke-Refresher metadata show --vm $id
    Check ($result.Exit -eq 0 -and $result.Output -match 'Provisioning pending') 'a block is found through WMI, by VM ID'
    Check ($result.Output -match 'Sensitive\s+2') '...with its two sensitive values'
    Check ($result.Output -notmatch 'hunter') '...which show does not print'

    $result = Invoke-Refresher metadata finish --vm $vmName --result complete
    Check ($result.Exit -eq 0) "finish succeeds ($($result.Output.Trim()))"

    $after = Get-Notes $id
    Write-Host '--- notes as Hyper-V now holds them ---'
    Write-Host $after
    Write-Host '---'
    Check ($after -notmatch 'hunter') 'the notes no longer hold the sensitive values'
    Check ($after.Contains('# Written by hand, with <markup> & "quotes" and é.')) '...and keep the comment, markup and all'
    Check ($after.StartsWith('Owned by the web team.') -and $after.TrimEnd().EndsWith('Do not delete.')) '...and the text outside the block'
    Check ($after -match "status: complete.*instance-id: $instanceId") '...and record the status and instance'
    # Hyper-V Manager's text box shows a bare LF as no line break, so this is the one to look at if it fails.
    Check ($after -match "Owned by the web team\.`r`n") '...and keep CRLF line ends through the WMI write'
    Check ($after -notmatch '&#13;|&amp;') '...with no escapes left in the text'

    foreach ($size in 4KB, 16KB, 64KB, 256KB, 1MB) {
        try {
            Set-VM -VM $vm -Notes ("#proof-metadata-begin`r`nuser-data: " + ('x' * $size) + "`r`n#proof-metadata-end")
            $read = Get-Notes $id
            Write-Host "info: notes of about $size characters: read back $($read.Length)"
        }
        catch {
            Write-Host "info: notes of about $size characters refused: $($_.Exception.Message)"
            break
        }
    }

    $before = Get-BiosGuid $id
    $result = Invoke-Refresher metadata new-instance-id --vm $vmName
    Check ($result.Exit -eq 0) "new-instance-id succeeds on a VM that is off ($($result.Output.Trim()))"
    $changed = Get-BiosGuid $id
    Check ($changed -ne $before) "the BIOS GUID changed ($before to $changed)"
    Check ($result.Output -match [regex]::Escape("i-$changed")) '...to the one it reported'
    Check ((Get-Notes $id) -match "`r`n") '...and the change left the notes'' CRLF alone'
    Check ($null -ne (Get-Settings $id)) '...and the VM ID did not'
}
finally {
    Remove-VM -VM $vm -Force
}
