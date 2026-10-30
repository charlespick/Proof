<#
.SYNOPSIS
  Installs and removes both MSIs and checks what they do, including that the refresher MSI refuses to install
  without its settings or host key.

.DESCRIPTION
  Needs an elevated session on a machine with Hyper-V. It changes the machine while it runs: it creates and deletes
  a test host key, %ProgramData%\Proof\refresher.json and the proof-refresher service, adds and removes
  NT SERVICE\proof-refresher in Hyper-V Administrators, and installs the service where any running VM would get
  test tokens. CI runs it on a throwaway runner. It refuses to start if Proof is already installed or
  configured here, and removes only what it created.

.EXAMPLE
  installer\Test-Installers.ps1 -RefresherMsi dist\proof-refresher-1.2.3-x64.msi -ClientMsi dist\proof-1.2.3-x64.msi -ExpectedVersion 1.2.3+abc1234
#>
param(
    [Parameter(Mandatory)] [string] $RefresherMsi,
    [Parameter(Mandatory)] [string] $ClientMsi,
    # What both programs' --version should print. Omit to skip the check.
    [string] $ExpectedVersion
)

$ErrorActionPreference = 'Stop'

$installDir = Join-Path $env:ProgramFiles 'Proof'
$settingsDir = Join-Path $env:ProgramData 'Proof'
$settingsFile = Join-Path $settingsDir 'refresher.json'
$keyName = 'Proof Installer Test Key'
$ksp = [System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
$machineKey = [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey
$logDir = Join-Path ([System.IO.Path]::GetTempPath()) "proof-installer-test-$PID"
New-Item -ItemType Directory -Force $logDir | Out-Null

$RefresherMsi = (Resolve-Path $RefresherMsi).Path
$ClientMsi = (Resolve-Path $ClientMsi).Path

function Check([bool] $condition, [string] $what) {
    if (-not $condition) { throw "FAILED: $what" }
    Write-Host "ok: $what"
}

function Invoke-Msi([string] $operation, [string] $msi, [string] $log) {
    $logPath = Join-Path $logDir "$log.log"
    $p = Start-Process msiexec -ArgumentList "$operation `"$msi`" /qn /norestart /l*v `"$logPath`"" -Wait -PassThru
    Write-Host "msiexec $operation $(Split-Path -Leaf $msi): exit $($p.ExitCode) (log $logPath)"
    $p.ExitCode
}

function Test-ServiceInstalled { [bool](Get-Service proof-refresher -ErrorAction SilentlyContinue) }

# The service's SID is derived from its name, so it can be checked for before and after the service exists.
$serviceSid = ((sc.exe showsid proof-refresher) -match 'SERVICE SID' -split ':\s*')[-1].Trim()

# By SID through ADSI: Get-LocalGroupMember fails on a member whose SID no longer resolves, which is exactly what a
# membership left behind by a removed service looks like.
function Test-InHyperVAdministrators {
    $group = ([System.Security.Principal.SecurityIdentifier]'S-1-5-32-578').Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
    $members = @(([ADSI]"WinNT://./$group,group").Invoke('Members')) | ForEach-Object {
        (New-Object System.Security.Principal.SecurityIdentifier($_.GetType().InvokeMember('objectSid', 'GetProperty', $null, $_, $null), 0)).Value
    }
    $members -contains $serviceSid
}
function Test-OnMachinePath { [bool](([Environment]::GetEnvironmentVariable('PATH', 'Machine') -split ';') -contains "$installDir\") }

Check (-not (Test-ServiceInstalled)) 'the proof-refresher service is not installed yet'
Check (-not (Test-Path $installDir)) "$installDir does not exist yet"
Check (-not (Test-Path $settingsFile)) "$settingsFile does not exist yet"
Check (-not [System.Security.Cryptography.CngKey]::Exists($keyName, $ksp, $machineKey)) "host key '$keyName' does not exist yet"
Check (-not (Test-InHyperVAdministrators)) 'NT SERVICE\proof-refresher is not in Hyper-V Administrators yet'

$createdSettingsDir = -not (Test-Path $settingsDir)
try {
    # The refresher's preconditions.
    Check ((Invoke-Msi '/i' $RefresherMsi 'refresher-no-settings') -eq 1603) 'the refresher MSI fails without refresher.json'
    Check (-not (Test-ServiceInstalled)) '...and leaves no service'

    New-Item -ItemType Directory -Force $settingsDir | Out-Null
    @{ Proof = @{ IssuerUrl = 'https://id.example.test'; HostKeyName = $keyName } } | ConvertTo-Json | Set-Content $settingsFile
    Check ((Invoke-Msi '/i' $RefresherMsi 'refresher-no-key') -eq 1603) 'the refresher MSI fails when the service cannot start (no host key)'
    Check (-not (Test-ServiceInstalled)) '...and leaves no service'
    Check (-not (Test-Path "$installDir\proof-refresher.exe")) '...and no files'
    Check (-not (Test-InHyperVAdministrators)) '...and takes the account back out of Hyper-V Administrators'

    # The key as configuration management would create it before installing (README.md).
    $parameters = [System.Security.Cryptography.CngKeyCreationParameters]::new()
    $parameters.Provider = $ksp
    $parameters.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey
    $parameters.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
    $parameters.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Signing
    [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::ECDsaP256, $keyName, $parameters).Dispose()

    Check ((Invoke-Msi '/i' $RefresherMsi 'refresher-install') -eq 0) 'the refresher MSI installs once settings and key exist'
    Check ((Get-Service proof-refresher).Status -eq 'Running') '...and the service is running'
    Check ((Get-Service proof-refresher).StartType -eq 'Automatic') '...and starts automatically'
    $startName = (Get-CimInstance Win32_Service -Filter "Name='proof-refresher'").StartName
    Check ($startName -eq 'NT SERVICE\proof-refresher') "...as NT SERVICE\proof-refresher (got $startName)"
    Check (Test-InHyperVAdministrators) '...which is in Hyper-V Administrators'
    $access = & "$installDir\proof-refresher.exe" key show 2>&1 | Out-String
    Check ($access -match 'NT SERVICE\\proof-refresher: read') '...and may use the host key'

    # A repair runs the grant again, which is how a new host key gets granted.
    & "$installDir\proof-refresher.exe" service revoke 2>&1 | Out-Null
    Check ((Invoke-Msi '/fa' $RefresherMsi 'refresher-repair') -eq 0) 'a repair succeeds'
    Check (Test-InHyperVAdministrators) '...and puts the account back in Hyper-V Administrators'
    Check ((Get-Service proof-refresher).Status -eq 'Running') '...and the service is running'
    # Settings an ordinary user could change are refused. The grant is explicit, so removing it leaves the inherited access.
    icacls $settingsFile /grant '*S-1-5-32-545:(M)' | Out-Null
    $refused = & "$installDir\proof-refresher.exe" key show 2>&1 | Out-String
    Check (($LASTEXITCODE -eq 1) -and ($refused -match 'Refusing the machine settings')) 'the refresher refuses settings Users can change'
    icacls $settingsFile /remove:g '*S-1-5-32-545' | Out-Null
    Check ((& "$installDir\proof-refresher.exe" key show 2>&1 | Out-String) -match 'Access:') '...and accepts them again once only administrators can'

    if ($ExpectedVersion) {
        $v = & "$installDir\proof-refresher.exe" --version
        Check ($v -eq $ExpectedVersion) "proof-refresher --version prints $ExpectedVersion (got $v)"
    }

    Check ((Invoke-Msi '/i' $ClientMsi 'client-install') -eq 0) 'the client MSI installs'
    Check (Test-OnMachinePath) "...and puts $installDir\ on the machine PATH"
    if ($ExpectedVersion) {
        $v = & "$installDir\proof.exe" --version
        Check ($v -eq $ExpectedVersion) "proof --version prints $ExpectedVersion (got $v)"
    }

    Check ((Invoke-Msi '/x' $RefresherMsi 'refresher-uninstall') -eq 0) 'the refresher MSI uninstalls'
    Check (-not (Test-ServiceInstalled)) '...and removes the service'
    Check (-not (Test-InHyperVAdministrators)) '...and takes the account out of Hyper-V Administrators'
    Check (Test-Path "$installDir\LICENSE.txt") '...and leaves the license the client still uses'
    Check ([System.Security.Cryptography.CngKey]::Exists($keyName, $ksp, $machineKey)) '...and leaves the host key'

    Check ((Invoke-Msi '/x' $ClientMsi 'client-uninstall') -eq 0) 'the client MSI uninstalls'
    Check (-not (Test-Path $installDir)) "...and removes $installDir"
    Check (-not (Test-OnMachinePath)) '...and takes it off the machine PATH'
}
finally {
    foreach ($msi in $RefresherMsi, $ClientMsi) {
        $null = Start-Process msiexec -ArgumentList "/x `"$msi`" /qn /norestart" -Wait -PassThru
    }
    if ([System.Security.Cryptography.CngKey]::Exists($keyName, $ksp, $machineKey)) {
        [System.Security.Cryptography.CngKey]::Open($keyName, $ksp, $machineKey).Delete()
    }
    Remove-Item -Force -ErrorAction SilentlyContinue $settingsFile
    if ($createdSettingsDir) { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $settingsDir }
}
