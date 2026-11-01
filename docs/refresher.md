# Installing the refresher

The refresher is a Windows service that runs on each Hyper-V host. It does two jobs:

- **Vouches for VMs.** About every five minutes, and as soon as a VM starts or live-migrates in, it signs a short-lived token naming the VM and writes it into the VM through Hyper-V Data Exchange (KVP). The VM's [client](client.md) trades that token for a JWT at the [issuer](issuer.md).
- **Serves instance metadata.** It answers requests from its VMs' cloud-init or Cloudbase-Init over a Hyper-V socket, using data you keep in each VM's notes.

The refresher holds a signing key that never leaves the host. You tell the issuer to trust that key by adding it to the allowlist.

## Requirements

- Windows Server with the Hyper-V role (tested on Windows Server 2025).
- The [issuer](issuer.md) deployed and reachable from the host.
- For each VM: the Data Exchange integration service enabled (it is by default).

## Install

The simplest path is the MSI from the [releases page](https://github.com/charlespick/Proof/releases), driven by your configuration management. The installer is deliberately strict: it refuses to install unless the host is already configured, so you never end up with a service that is running but can't do anything.

From an elevated PowerShell prompt:

```powershell
# 1. Settings
New-Item -ItemType Directory -Force $env:ProgramData\Proof
'{ "Proof": { "IssuerUrl": "https://id.example.com", "Cluster": "prod" } }' |
    Set-Content $env:ProgramData\Proof\refresher.json

# 2. The host key: a non-exportable P-256 machine key. Safe to run repeatedly.
$ksp = [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
if (-not [Security.Cryptography.CngKey]::Exists('Proof Host Key', $ksp, [Security.Cryptography.CngKeyOpenOptions]::MachineKey)) {
    $p = [Security.Cryptography.CngKeyCreationParameters]::new()
    $p.Provider = $ksp
    $p.KeyCreationOptions = [Security.Cryptography.CngKeyCreationOptions]::MachineKey
    $p.ExportPolicy = [Security.Cryptography.CngExportPolicies]::None
    $p.KeyUsage = [Security.Cryptography.CngKeyUsages]::Signing
    [Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::ECDsaP256, 'Proof Host Key', $p).Dispose()
}

# 3. Install
msiexec /i proof-refresher-<version>-x64.msi /qn /l*v proof-refresher-install.log
```

Then print the host's allowlist entry:

```powershell
& "C:\Program Files\Proof\proof-refresher.exe" key show
```

Add the printed entry to the issuer's allowlist, through your usual review process. Within seconds the issuer will accept tokens from this host.

If the install fails (`msiexec` exits 1603), the Application event log, source `proof-refresher`, says why. The usual causes are missing settings, a missing host key, or an `IssuerUrl` that is not valid.

### Without the MSI

`proof-refresher key create` creates the key and prints the allowlist entry. Then register the service and give it the access it needs:

```powershell
sc.exe create proof-refresher binPath= "C:\Program Files\Proof\proof-refresher.exe" start= auto
& "C:\Program Files\Proof\proof-refresher.exe" service grant
```

## Settings

Settings are read from `appsettings.json` next to the executable, then `%ProgramData%\Proof\refresher.json`, then environment variables (`Proof__Name`).

| Setting | Default | Meaning |
| ------- | ------- | ------- |
| `IssuerUrl` | required | Exactly the issuer's URL |
| `HostId` | the computer name, lowercase | This host's name in the allowlist |
| `Cluster` | none | The failover cluster name. Use the same value on every host in the cluster, and omit it on a standalone host |
| `HostKeyName` | `Proof Host Key` | Name of the key. Use a new name to rotate |
| `MetadataEnabled` | `true` | Serve instance metadata to VMs |
| `UnsetMetadataHandler` | `minimal` | What a VM with no metadata gets: `minimal` gives its instance ID and hostname, `404` refuses |

Only administrators may write the settings. The refresher checks the ownership and permissions of `%ProgramData%\Proof` and `refresher.json` when it starts and refuses to run if someone else could change them. The error names the account and gives the command that fixes it.

## Checking that it works

```powershell
& "C:\Program Files\Proof\proof-refresher.exe" once
```

This writes a token to every running VM now and reports what happened. Inside a VM with the [client](client.md) installed, `proof status` should then show a host token.

The service runs as its own virtual account, `NT SERVICE\proof-refresher`, with no password. The installer makes that account a member of Hyper-V Administrators, which it needs to see VMs. Without that membership Hyper-V shows it no VMs and nothing is written, with no error.

## Rotating the host key

1. Create a key under a new name (`proof-refresher key create`), and add its entry to the allowlist alongside the old one.
2. Change `HostKeyName` and run `proof-refresher service grant` (or repair the MSI with `msiexec /fa`), then restart the service.
3. After the old key's last token has expired, 20 minutes at most, remove the old key from the allowlist.

A rebuilt host gets a new key and a new allowlist entry. Host keys cannot be exported, so there is nothing to restore.

## Monitoring

Metrics are on the `Proof.Refresher` meter:

- `proof.refresher.kvp_writes`, by outcome
- `proof.refresher.oldest_token_age`. Alert as it nears 20 minutes.
- `proof.refresher.running_vms`

A VM whose writes keep failing is logged as a warning, and as an error once its token has expired. Logs never contain tokens.

## Instance metadata

The refresher can also give VMs their hostname, SSH keys and cloud-init user data, much as a public cloud does. You write the data into the VM's notes in Hyper-V, and the VM reads it from an EC2-compatible endpoint. The [client](client.md#instance-metadata) page covers the VM side.

Add a block between two marker lines to the VM's notes, using Hyper-V Manager or `Set-VM -Notes`. The rest of your notes are left alone.

```yaml
Owned by the web team.
#proof-metadata-begin
meta-data:
  local-hostname: web01
  public-keys:
    - ssh-ed25519 AAAA... you@example.com
user-data: !sensitive |
  #cloud-config
  password: change-me
  phone_home:
    url: http://127.0.0.1:8169/proof/v1/provisioning/complete
    post: [instance_id]
#proof-metadata-end
```

- The marker lines start in the first column. The top-level keys are `meta-data`, `user-data` and `provisioning`.
- Mark secrets with `!sensitive`. When provisioning finishes, the host replaces each one in the notes with `!cleared "<time>"`, so the secret doesn't sit in the VM's settings forever.
- `instance-id` comes from the VM's BIOS GUID and can't be set. `local-hostname` defaults to the VM's name.
- Hyper-V allows 32,768 characters of notes.

**Write the block before the VM's first boot.** Without one, the VM gets its instance ID and hostname only, and cloud-init treats the instance as done. A block added afterwards does nothing until you give the VM a new instance ID (below).

A block that can't be used, for example with a mistyped tag, serves nothing at all, and the refresher logs why. That is deliberate: it's better for provisioning to wait than to run without your user data or leave a secret behind.

Useful commands:

```powershell
$p = "C:\Program Files\Proof\proof-refresher.exe"
& $p metadata show --vm web01                     # what the VM would be served (secrets are never printed)
& $p metadata finish --vm web01 --result complete # clear secrets now, if the guest will never report
& $p metadata new-instance-id --vm web02          # make a clone a new instance (VM must be off)
```

**Cloning.** A copy that keeps the original's BIOS GUID is the same instance to cloud-init, so it won't be provisioned again. To make a copy a new instance, run `new-instance-id` on it while it is off, and set `provisioning: pending` in its notes if the source had finished.

Avoid checkpointing a VM that holds secrets in its notes, because checkpoints keep their own copy of the VM's settings.

Next: [put the client in your VM images](client.md).
