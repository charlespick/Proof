# Installing the refresher

The refresher runs on each Hyper-V host. It does two jobs, as two Windows services installed together:

- **Vouches for VMs** (`proof-refresher`). For each VM whose notes have an [`identity:` block](#vm-identity), it signs a short-lived token naming the VM and its identity and writes it into the VM through Hyper-V Data Exchange (KVP). It does so about every five minutes, as soon as a VM starts or live-migrates in, and as soon as a VM's identity changes. The VM's [client](client.md) trades that token for a JWT at the [issuer](issuer.md).
- **Serves instance metadata** (`proof-metadata-host`). It answers requests from its VMs' cloud-init or Cloudbase-Init over a Hyper-V socket, using data you keep in each VM's notes.

`proof-refresher` holds a signing key that never leaves the host. You tell the issuer to trust that key by adding it to the allowlist. `proof-metadata-host` talks to guests, so it can't use that key.

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
'{ "Proof": { "IssuerUrl": "https://id.example.com" } }' |
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

`proof-refresher key create` creates the key and prints the allowlist entry. Then register the services and give them the access they need:

```powershell
sc.exe create proof-refresher binPath= "C:\Program Files\Proof\proof-refresher.exe" start= auto
sc.exe --% create proof-metadata-host binPath= "\"C:\Program Files\Proof\proof-refresher.exe\" metadata serve" start= auto
& "C:\Program Files\Proof\proof-refresher.exe" service grant
```

## Settings

Settings are read from `appsettings.json` next to the executable, then `%ProgramData%\Proof\refresher.json`, then environment variables (`Proof__Name`).

| Setting | Default | Meaning |
| ------- | ------- | ------- |
| `IssuerUrl` | required | Exactly the issuer's URL |
| `HostId` | the computer name, lowercase | This host's name in the allowlist |
| `HostKeyName` | `Proof Host Key` | Name of the key. Use a new name to rotate |
| `MetadataEnabled` | `true` | Serve instance metadata to VMs |
| `UnsetMetadataHandler` | `minimal` | What a VM with no metadata gets: `minimal` gives its instance ID and hostname, `404` refuses |

Only administrators may write the settings. The refresher checks the ownership and permissions of `%ProgramData%\Proof` and `refresher.json` when it starts and refuses to run if someone else could change them. The error names the account and gives the command that fixes it.

## Checking that it works

```powershell
& "C:\Program Files\Proof\proof-refresher.exe" once
```

This gives every running VM the token its notes call for now, and reports what happened: `ok` with the subject for a VM with an identity, `none` for a VM without one, and `refused` with the reason for a VM whose identity can't be used. Inside a VM with an identity and the [client](client.md) installed, `proof status` should then show a host token.

Each service runs as its own virtual account, `NT SERVICE\proof-refresher` and `NT SERVICE\proof-metadata-host`, with no password. The installer makes both accounts members of Hyper-V Administrators, which they need to see VMs. Without that membership Hyper-V shows them no VMs and nothing is written, with no error. Only `NT SERVICE\proof-refresher` gets read on the host key.

## Rotating the host key

1. Create a key under a new name (`proof-refresher key create`), and add its entry to the allowlist alongside the old one.
2. Change `HostKeyName` and run `proof-refresher service grant` (or repair the MSI with `msiexec /fa`), then restart the `proof-refresher` service.
3. After the old key's last token has expired, 20 minutes at most, remove the old key from the allowlist.

A rebuilt host gets a new key and a new allowlist entry. Host keys cannot be exported, so there is nothing to restore.

## Monitoring

Metrics are on the `Proof.Refresher` meter:

- `proof.refresher.kvp_writes`, by outcome
- `proof.refresher.kvp_removals`, by outcome: tokens taken from VMs that lost their identity
- `proof.refresher.oldest_token_age`, among VMs with an identity. Alert as it nears 20 minutes.
- `proof.refresher.running_vms`
- `proof.refresher.enrolled_vms`: running VMs with a usable identity
- `proof.refresher.identity_errors`: running VMs that get no token because their identity can't be used or doesn't fit. Alert when it is above zero.

A VM whose writes keep failing is logged as a warning, and as an error once its token has expired. A VM whose identity can't be used is logged as an error, with the reason, when that starts. Logs never contain tokens or values from the notes.

## VM identity

The refresher signs a token only for a VM that has opted in, much like turning on a managed identity for a cloud resource. To opt a VM in, add an `identity:` block to the Proof block in its notes, using Hyper-V Manager or `Set-VM -Notes`. It sits alongside the [instance metadata](#instance-metadata), and either can be used without the other.

```yaml
#proof-metadata-begin
identity:
  tenant: acme
  assigned-id: web01.prod.example.com
  security-tags: [puppet, ssh-ca]
meta-data:
  hostname: web01
#proof-metadata-end
```

The issuer puts these values into every JWT the VM gets, as claims of their own and in its subject, `tenant:acme:assignedID:web01.prod.example.com:vmID:<vm-id>`. The [issuer page](issuer.md#claims) describes the claims for consumers.

- `tenant` and `assigned-id` are required. `assigned-id` is whatever you choose, such as a hostname or an FQDN.
- `security-tags` is optional, and is a list. Use `[]`, or leave it out, for none.
- No other keys are allowed under `identity:`, so a misspelled `security-tags` is caught instead of silently granting nothing.
- `!sensitive` and other tags aren't allowed. Identity is not a secret, and it stays in the notes when provisioning finishes.
- The guest is never served the `identity:` block. It only ever sees the signed token.

### Value rules

The values go into a subject separated by `:`, so they are restricted to keep it unambiguous.

| Field | Rule |
| ----- | ---- |
| `tenant` | 1 to 63 lowercase letters, digits, `.`, `-` or `_`, starting with a letter or digit |
| `assigned-id` | 1 to 253 of the same characters |
| `security-tags` | At most 16 tags, each 1 to 63 of the same characters, with no tag listed twice |

The refresher lowercases `tenant` and `assigned-id` before checking them, since DNS names are case-insensitive. Tags are not lowercased, so a tag with a capital letter is refused.

The whole token must also fit in one Data Exchange value, 1,023 characters. With an issuer URL and host ID of up to 32 characters each, an identity fits if its tenant, assigned ID and tags, counting 3 more characters for each tag, add up to at most 340 characters. The longest tenant and assigned ID always fit together. The VM's name is left out of the token first if that makes it fit. If it still doesn't, the VM gets no token and the refresher logs an error naming the VM. Identity values are never shortened or dropped.

### What happens when

| Situation | What the refresher does |
| --------- | ----------------------- |
| No `identity:` block | Signs nothing, and removes any token the VM has |
| An `identity:` block that can't be used, or a Proof block that can't be used for any reason | Signs nothing, removes any token, and logs why without quoting the values |
| A token that doesn't fit | The same |
| The notes can't be read (a Hyper-V error) | Changes nothing and retries shortly. An existing token expires on its own |
| The identity changes while the VM runs | Writes a token with the new identity within about a second |
| The block is removed or broken while the VM runs | Removes the token within about a second |

The refresher never uses the VM's name, its hostname or its BIOS GUID in place of a missing value. Names can change, and they are not identity.

`proof-refresher metadata show --vm <name>` shows the identity the refresher reads, as the subject it leads to, or says why the block can't be used.

### Changes apply at once

The refresher watches Hyper-V for changes to VM notes and re-signs a VM's token as soon as its identity changes; measured on Windows Server 2025, it takes under a second. Edits that leave the identity as it was, including the metadata service clearing secrets, change nothing. The five-minute pass still runs, and catches any change whose event was missed.

Replacing the token in the VM stops the normal path from getting the old identity straight away. It isn't instant revocation: a host token already copied out of the VM stays valid for up to 20 minutes, and a JWT already issued for up to 10. See [security](security.md#vm-identity-and-who-sets-it).

## Instance metadata

The refresher can also give VMs their hostname, SSH keys, network configuration and cloud-init user data, much as a public cloud does. You write the data into the VM's notes in Hyper-V, and the VM reads it from an endpoint in OpenStack's metadata format. The [client](client.md#instance-metadata) page covers the VM side.

Add a block between two marker lines to the VM's notes, using Hyper-V Manager or `Set-VM -Notes`. The rest of your notes are left alone.

```yaml
Owned by the web team.
#proof-metadata-begin
meta-data:
  hostname: web01
  public_keys:
    you: ssh-ed25519 AAAA... you@example.com
  admin_pass: !sensitive change-me
network-data: |
  {
    "links": [{ "id": "eth0", "type": "phy", "ethernet_mac_address": "00:15:5d:01:02:03" }],
    "networks": [{ "id": "net0", "link": "eth0", "type": "ipv4",
                   "ip_address": "192.0.2.10", "netmask": "255.255.255.0",
                   "routes": [{ "network": "0.0.0.0", "netmask": "0.0.0.0", "gateway": "192.0.2.1" }] }],
    "services": [{ "type": "dns", "address": "192.0.2.53" }]
  }
user-data: !sensitive |
  #cloud-config
  password: change-me
  phone_home:
    url: http://127.0.0.1:8169/proof/v1/provisioning/complete
    post: [instance_id]
#proof-metadata-end
```

- The marker lines start in the first column. The top-level keys are `identity` ([above](#vm-identity)), `meta-data`, `user-data`, `network-data` and `provisioning`.
- Mark secrets with `!sensitive`. When provisioning finishes, the host replaces each one in the notes with `!cleared "<time>"`, so the secret doesn't sit in the VM's settings forever.
- `meta-data` becomes `meta_data.json`, with OpenStack's names: `hostname`, `public_keys` and `admin_pass`, the Administrator password that Cloudbase-Init sets. `hostname` defaults to the VM's name. `public_keys` may be one key, a list or a mapping from name to key; it is always served as a mapping, which is what Cloudbase-Init reads. EC2's names, such as `local-hostname`, are refused, since the clients would ignore them.
- `uuid`, the instance ID, is the VM's BIOS GUID and can't be set. It matches the SMBIOS UUID the guest sees, which cloud-init checks on every later boot.
- `network-data` is OpenStack's [`network_data.json`](https://docs.openstack.org/nova/latest/user/metadata.html#openstack-format-metadata) as a string. It is served exactly as written and only checked to be a JSON object; cloud-init and Cloudbase-Init apply it. Its links name each adapter by MAC address, so give the VM's adapters static MACs (`Set-VMNetworkAdapter -StaticMacAddress`) before the first boot. Leave it out and the VM uses DHCP.
- Hyper-V allows 32,768 characters of notes.

**Write the block before the VM's first boot.** Without one, the VM gets its instance ID and hostname only, and cloud-init treats the instance as done. A block added afterwards does nothing until you give the VM a new instance ID (below).

A block that can't be used, for example with a mistyped tag, serves nothing at all and gives the VM no token, and both services log why. That is deliberate: it's better for provisioning to wait than to run without your user data or leave a secret behind.

Useful commands:

```powershell
$p = "C:\Program Files\Proof\proof-refresher.exe"
& $p metadata show --vm web01                     # what the VM would be served (secrets are never printed)
& $p metadata finish --vm web01 --result complete # clear secrets now, if the guest will never report
& $p metadata new-instance-id --vm web02          # make a clone a new instance (VM must be off)
```

**Cloning.** A copy that keeps the original's BIOS GUID is the same instance to cloud-init, so it won't be provisioned again. To make a copy a new instance, run `new-instance-id` on it while it is off, and set `provisioning: pending` in its notes if the source had finished. Give the copy its own MAC address and `network-data` too, or it comes up with the original's address.

Avoid checkpointing a VM that holds secrets in its notes, because checkpoints keep their own copy of the VM's settings.

Next: [put the client in your VM images](client.md).
