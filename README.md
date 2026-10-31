# Proof

Proof lets a Hyper-V VM prove which VM it is to on-premises services. The Hyper-V host signs a short-lived token and writes it into the VM over KVP (Hyper-V Data Exchange). The VM trades that token for audience-specific JWTs, which consumers verify against the issuer's published keys without calling the host or a database.

Proof does authentication only. Consumers decide what an identity may do. See [Design.md](docs/Design.md) for the full specification.

Separately, the same packages serve an [EC2-style instance metadata API](#instance-metadata) for cloud-init and Cloudbase-Init, from each VM's Hyper-V notes.

## Components

| Project | Path | Role |
| ------- | ---- | ---- |
| `Proof.Refresher` | `src/Proof.Refresher` | Windows service on each Hyper-V host. Signs a host token for each VM and writes it into that VM's KVP pool about every 5 minutes. Also answers VMs' instance metadata requests over Hyper-V sockets. |
| `Proof.Issuer` | `src/Proof.Issuer` | ASP.NET Core service on Kubernetes. Verifies host tokens against the host-key allowlist, mints audience-specific JWTs at `/token` (RFC 8693), and serves the OIDC discovery document and JWKS. |
| `Proof.Client` | `src/Proof.Client` | The `proof` command on every VM image. Reads the host token from KVP, calls the issuer, and prints or writes the issued JWT. |
| `Proof.Metadata` | `src/Proof.Metadata` | The `proof-metadata` service on every VM image. Serves the instance metadata API on `127.0.0.1`, from the host over a Hyper-V socket. |
| `Proof.Shared` | `src/Proof.Shared` | Class library shared by the programs: claim names, token types, validation settings, KVP limits and the Hyper-V socket protocol. |

## Repository layout

```
Proof.slnx
build/
  Version.targets       versions from git tags
docs/
  Design.md
installer/              Windows MSIs (WiX)
  Proof.Refresher.Installer/
  Proof.Client.Installer/
packaging/
  debian/               the client .deb
src/
  Proof.Shared/
  Proof.Issuer/         includes the Dockerfile
  Proof.Refresher/
  Proof.Client/
  Proof.Metadata/
tests/
  Proof.Tests/
```

## Building and testing

Requires .NET SDK 10.0.302 exactly, as `global.json` pins, because the lock files record the packages that SDK bundles (such as ILLink). To move to a newer SDK, change `global.json` and the SDK image in the Dockerfile together, then regenerate the lock files. Tests use [xUnit v3](https://xunit.net/). NuGet versions are pinned in each project's `packages.lock.json`, which also cover the `win-x64`, `linux-x64` and `linux-arm64` publishes. CI restores in locked mode, so a change to a package reference needs `dotnet restore Proof.slnx --force-evaluate` and the updated lock files committed.

```sh
dotnet build Proof.slnx
dotnet test --solution Proof.slnx
```

## Packages and releases

| Package | Built by | Contents |
| ------- | -------- | -------- |
| `proof-refresher-<version>-x64.msi` | `dotnet build installer/Proof.Refresher.Installer/Proof.Refresher.Installer.wixproj -c Release` (Windows) | `proof-refresher.exe` as the `proof-refresher` service |
| `proof-<version>-x64.msi` | `dotnet build installer/Proof.Client.Installer/Proof.Client.Installer.wixproj -c Release` (Windows) | `proof.exe`, on the machine `PATH`, and `proof-metadata.exe` as the `proof-metadata` service |
| `proof_<version>_amd64.deb` | `dotnet publish` of `src/Proof.Client` and `src/Proof.Metadata` with `-c Release -r linux-x64` to one folder, then `packaging/debian/build-deb.sh` | `/usr/bin/proof`, and `/usr/bin/proof-metadata` as the `proof-metadata` systemd service |
| `ghcr.io/charlespick/proof-issuer:<version>` | `docker build -f src/Proof.Issuer/Dockerfile .` | The issuer, for `linux/amd64` and `linux/arm64` |

Each MSI installs into `C:\Program Files\Proof` with `LICENSE.txt`. They build with [WiX](https://wixtoolset.org/) 5, which NuGet restores. `installer/Test-Installers.ps1` installs and removes both MSIs and checks what they do; it changes the machine, so CI runs it on a throwaway runner.

[CI](.github/workflows/ci.yml) tests on Windows and Linux and builds every package on every push. A `v*` tag on a commit on `main` also publishes a GitHub release with the MSIs, the .deb and `SHA256SUMS`, and pushes the image (`latest` too, unless it is a prerelease).

**Versions** come from the nearest tag, read by `git describe` in [build/Version.targets](build/Version.targets). Tag releases `vMAJOR.MINOR.PATCH`, with an optional dotted prerelease such as `v1.3.0-rc.1` (not `rc1`, which sorts as a string). Commits after a tag build as a prerelease of the next patch, which sorts below any tag that follows:

| HEAD | Version | MSI ProductVersion | FileVersion | .deb version |
| ---- | ------- | ------------------ | ----------- | ------------ |
| at `v1.2.3` | `1.2.3` | `1.2.3` | `1.2.3.0` | `1.2.3` |
| 4 commits after `v1.2.3` | `1.2.4-0.dev.4` | `1.2.4` | `1.2.4.4` | `1.2.4~0.dev.4` |
| at `v1.3.0-rc.1` | `1.3.0-rc.1` | `1.3.0` | `1.3.0.0` | `1.3.0~rc.1` |
| 4 commits after `v1.3.0-rc.1` | `1.3.0-rc.1.dev.4` | `1.3.0` | `1.3.0.4` | `1.3.0~rc.1.dev.4` |

Windows Installer compares only the three-part ProductVersion. An MSI upgrades any installed build with a lower or equal ProductVersion in place, and refuses to install over a higher one. So builds of one version, prereleases included, replace each other in either direction, and going back to an older version means uninstalling first. The fourth FileVersion field tells builds of one version apart in Explorer. `--version` on both programs prints the full version and commit, for example `1.2.4-0.dev.4+1a2b3c4`.

A build outside a git clone needs `-p:ProofVersion=<version>`. The container build takes it as `--build-arg VERSION=<version>`.

## Running the issuer

The issuer reads its settings from the `Proof` configuration section (environment variables use `Proof__Name`):

| Setting | Default | Meaning |
| ------- | ------- | ------- |
| `IssuerUrl` | required | `https`, no trailing slash. The `iss` of issued JWTs and the `aud` host tokens must carry |
| `AllowlistPath` | required | Host allowlist YAML (Design.md 7.2). Mount the ConfigMap as a directory, not a subPath |
| `AllowlistPollInterval` | `00:00:10` | How often the allowlist is reread. An invalid file is refused and the previous list kept |
| `SigningKeyPath` | required | PEM ECDSA P-256 private key (SEC1 or PKCS#8) |
| `AdditionalPublicKeyPaths` | none | PEM public keys also published in the JWKS, for rotation |
| `IssuedTokenLifetime` | `00:05:00` | At most `00:10:00` |
| `AllowedAudiences` | none (any) | If set, other audiences get `invalid_target` |
| `TokenRequestsPerMinute` | `60` | Rate limit per source address on `/token` |
| `TrustedProxies` | none | Addresses or CIDR networks of the ingress. Only these may set the source address with `X-Forwarded-For` |

Issued JWTs name the VM as `sub` = `cluster:<cluster>/<vmid>`, or `host:<host>/<vmid>` for a host whose allowlist entry has no `cluster`. Hyper-V keeps VM IDs unique within a failover cluster or a standalone host, but an import or a restore elsewhere keeps the ID, so the VM ID alone is not an identity. The scope comes from the allowlist entry of the key that signed the host token, never from the token's claims, and a host token whose `cluster` differs from that entry (or has one when the entry has none) is refused. A VM keeps its subject when it live-migrates within its cluster; it gets a new one if it moves to another cluster or standalone host, or if its host joins or leaves a cluster on the allowlist. Host and cluster names are 1 to 253 letters, digits, `.`, `-` or `_`, starting with a letter or digit, so a subject parses unambiguously.

Endpoints: `POST /token`, `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json`, `GET /healthz/live`, and `GET /healthz/ready` (ready once an allowlist has loaded).

To try it locally:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out signing-key.pem
Proof__IssuerUrl=https://id.example Proof__AllowlistPath=allowlist.yaml Proof__SigningKeyPath=signing-key.pem dotnet run --project src/Proof.Issuer
```

Behind an ingress, every connection comes from the ingress, so without `TrustedProxies` all callers share one rate-limit bucket. List the ingress pods' network in `TrustedProxies` (for example `Proof__TrustedProxies__0=10.42.0.0/16`): the issuer then takes the source address from the rightmost `X-Forwarded-For` entry, the one the ingress added, and only on connections from those addresses. The issuer refuses to start with `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true`, because that trusts forwarded headers from any address that can reach the pod. The signing key is read at startup, so a rotation takes effect when the pods roll.

### Container image

The image runs the issuer as a non-root user (UID 1654) on a chiseled ASP.NET image, which has no shell. It serves HTTP on port 8080 and logs JSON to stdout. Two settings have defaults in the image, so only `Proof__IssuerUrl` must be set:

| Setting | Image default | Mount |
| ------- | ------------- | ----- |
| `Proof__AllowlistPath` | `/etc/proof/allowlist/allowlist.yaml` | The allowlist ConfigMap, as a directory |
| `Proof__SigningKeyPath` | `/etc/proof/signing/signing-key.pem` | The signing key Secret |

On Kubernetes, point the liveness probe at `/healthz/live` and the readiness probe at `/healthz/ready`, both on port 8080, and terminate TLS at the ingress. Two replicas mount the same Secret (Design.md 8). The issuer writes nothing to disk, so `readOnlyRootFilesystem: true` should work; that has not been tried yet.

To run it on its own with Docker, the files must be readable by UID 1654:

```sh
docker run -d --name proof-issuer -p 8080:8080 \
  -e Proof__IssuerUrl=https://id.example \
  -v "$PWD/allowlist:/etc/proof/allowlist:ro" \
  -v "$PWD/signing:/etc/proof/signing:ro" \
  ghcr.io/charlespick/proof-issuer:1.2.3
```

Clients only talk to an `https` issuer. Without a proxy in front of it, Kestrel can serve TLS itself: add `-e ASPNETCORE_HTTPS_PORTS=8443 -e ASPNETCORE_Kestrel__Certificates__Default__Path=/etc/proof/tls/tls.crt -e ASPNETCORE_Kestrel__Certificates__Default__KeyPath=/etc/proof/tls/tls.key`, mount the certificate there, and publish port 8443.

## Running the refresher

The refresher runs on each Hyper-V host, elevated or as a service. It writes a new host token to `proof.v1.token` in a VM's KVP External pool when that VM has none from this host yet, or its token is 5 minutes old. Tokens live 20 minutes.

It subscribes to Hyper-V's WMI events for VMs entering the Running state. A VM that starts or live-migrates in gets this host's token at once, measured at about 200 ms after `Start-VM` and about 260 ms after a cluster live migration. A migrated VM also arrives with its previous host's token, because KVP items travel with it. A scheduled pass every 5 minutes renews tokens and catches missed events. After a failed write or a lost subscription, the next pass comes after 30 seconds instead.

The host key is an ECDSA P-256 machine key in the CNG Microsoft Software Key Storage Provider, created non-exportable. No TPM is needed.

Settings come from `appsettings.json` next to the executable, then `%ProgramData%\Proof\refresher.json`, then environment variables (`Proof__Name`):

| Setting | Default | Meaning |
| ------- | ------- | ------- |
| `IssuerUrl` | required | Exactly the issuer's `IssuerUrl`. Host tokens carry it as `aud` |
| `HostId` | computer name, lowercase | This host's `host` in the allowlist; host tokens carry it as `iss` |
| `Cluster` | none | This host's `cluster` in the allowlist. Omit for a standalone host |
| `HostKeyName` | `Proof Host Key` | CNG key name. Use a new name to rotate (Design.md 7.3) |
| `ScanInterval` | `00:05:00` | Time between scheduled passes, at most 5 minutes. Starts and migrations get their own pass |
| `MetadataEnabled` | `true` | Serve [instance metadata](#instance-metadata). Off, no socket is opened |
| `UnsetMetadataHandler` | `minimal` | What a VM with no metadata block gets. `minimal`: its instance ID and hostname, and a phone-home is recorded by adding a block with only the status. `404`: not found, and nothing is recorded. Any other value stops the refresher starting |

Any user may create folders and files under `%ProgramData%` and then owns them, so a user could create `Proof\refresher.json` before an administrator does and edit it later. The refresher refuses to start, and its commands refuse to run, if `%ProgramData%\Proof` or `refresher.json` is a link, is owned by anyone but SYSTEM, Administrators or TrustedInstaller, or lets anyone else change or replace the file. The error names the account and the `icacls` command that fixes it. A folder and file an elevated administrator creates, as below, pass with the access they inherit from `%ProgramData%`.

The MSI is meant for configuration management, and fails without changing anything unless the host is already set up: it needs `%ProgramData%\Proof\refresher.json`, and the service must start, which it does only with valid settings and a usable host key. When the service cannot start, `msiexec` exits with 1603 after about 45 seconds (Windows waits 30 seconds for the service) (error 1920 in the MSI log), and the Application event log (source `proof-refresher`) says why. Set up a host (elevated):

```powershell
New-Item -ItemType Directory -Force $env:ProgramData\Proof
'{ "Proof": { "IssuerUrl": "https://id.corp.example", "Cluster": "prod" } }' | Set-Content $env:ProgramData\Proof\refresher.json

# The host key, created as `proof-refresher key create` would: a non-exportable P-256 machine key that SYSTEM and
# Administrators may use. Skipped when it exists, so this can run on every configuration pass.
$ksp = [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
if (-not [Security.Cryptography.CngKey]::Exists('Proof Host Key', $ksp, [Security.Cryptography.CngKeyOpenOptions]::MachineKey)) {
    $p = [Security.Cryptography.CngKeyCreationParameters]::new()
    $p.Provider = $ksp
    $p.KeyCreationOptions = [Security.Cryptography.CngKeyCreationOptions]::MachineKey
    $p.ExportPolicy = [Security.Cryptography.CngExportPolicies]::None
    $p.KeyUsage = [Security.Cryptography.CngKeyUsages]::Signing
    [Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::ECDsaP256, 'Proof Host Key', $p).Dispose()
}

msiexec /i proof-refresher-1.2.3-x64.msi /qn /l*v proof-refresher-install.log
& "C:\Program Files\Proof\proof-refresher.exe" key show   # prints the allowlist entry to add by pull request
& "C:\Program Files\Proof\proof-refresher.exe" once       # write to every running VM now and report
```

The MSI installs the `proof-refresher` service to start automatically and restart a minute after a crash. It runs as its virtual account, `NT SERVICE\proof-refresher`, which has no password and needs no network access. Before the service first starts, the MSI runs `proof-refresher service grant`, which gives that account:

- membership of Hyper-V Administrators. Without it, Hyper-V shows the account no VMs, so the refresher writes nothing and logs no error, and `proof.refresher.running_vms` reads 0;
- read on the host key named in the settings;
- the `proof-refresher` event log source, which only an administrator can register;
- the instance metadata service's registration with Hyper-V (not a right of the account, but it needs an administrator too).

Windows Installer cannot install a service under a virtual account directly, so the MSI installs it as Local System and the grant step switches it to the virtual account. Upgrades and repairs run the grant again. After creating a new host key to rotate (Design.md 7.3), run `proof-refresher service grant`, or repair with `msiexec /fa`, before restarting the service. Uninstalling takes the account out of Hyper-V Administrators, unregisters the metadata socket, removes the service, and leaves the settings, the host key and the event source.

Without the MSI, `proof-refresher key create` makes the key and prints the entry. Then `sc.exe create proof-refresher binPath= "C:\Program Files\Proof\proof-refresher.exe" start= auto` and `proof-refresher service grant` set up the service as the MSI would. `proof-refresher key show` prints the entry again, along with who may use the key.

Publish as a self-contained single file (NativeAOT does not work, because WMI needs built-in COM). The project sets self-contained and single-file whenever a runtime is given:

```sh
dotnet publish src/Proof.Refresher -c Release -r win-x64
```

Metrics are on the `Proof.Refresher` meter:
- `proof.refresher.kvp_writes`, by outcome
- `proof.refresher.oldest_token_age`: alert as it nears 20 minutes
- `proof.refresher.running_vms`

A VM whose writes keep failing is logged as a warning, and as an error once its token has expired. Logs never contain tokens.

## Running the client

`proof` runs inside each VM. It reads the host token from KVP, sends it to the issuer's `/token`, and prints the issued JWT or writes it to a file:

```sh
proof token --audience my-service                  # print a JWT for my-service
proof token --audience sts.example --out /run/proof/token   # write it for an SDK that reads a token file
proof status                                       # show the host token (never printed) and anything wrong
```

| Option | Meaning |
| ------ | ------- |
| `--audience <aud>` | Required for `token`. One audience, up to 256 characters, no spaces |
| `--out <path>` | Write the JWT to `<path>` (no trailing newline) in one rename, so readers never see a partial file. A new file is mode 0600; a replaced file keeps its mode. The owner is whoever runs `proof` |
| `--wait <seconds>` | Wait up to that long for an unexpired host token first, for use early in boot |
| `--config <path>` | Read settings from `<path>` instead of the default |

Exit codes: 0 success, 1 failure, 2 usage, 3 no host token yet. The refresher may not have written one yet, so callers should treat 3 as "retry shortly". When the issuer refuses an exchange, `proof` reads the host token's claims without verifying them and says what it can see: an expired token, a clock behind the host's, or an issuer URL mismatch. The issuer's log has the actual reason.

Settings are in `/etc/proof/config.json` on Linux and `%ProgramData%\Proof\config.json` on Windows. Unknown names are refused:

| Setting | Default | Meaning |
| ------- | ------- | ------- |
| `IssuerUrl` | required | Exactly the issuer's `IssuerUrl`. Baked into the image, never learned from KVP |
| `TokenEndpoint` | `IssuerUrl` + `/token` | Set it when `/token` is served at an internal name while the discovery documents are hosted publicly (Design.md 6.5) |
| `CaBundlePath` | system store | PEM CA certificates. When set, the issuer's certificate must chain to one of them, and the system store is not used. Relative to the settings file |

On Windows, `proof` refuses `%ProgramData%\Proof\config.json` under the same rule as the refresher's settings: SYSTEM, Administrators or TrustedInstaller must own it and its folder, and no one else may change it. A file passed with `--config` is not checked.

Where the client reads KVP:

- **Linux**: `/var/lib/hyperv/.kvp_pool_0`, the External pool file `hv_kvp_daemon` keeps (512-byte key and 2048-byte value records). Reads take an fcntl read lock, so they never see the daemon halfway through a rewrite. Upstream, the daemon creates the file mode 0644, so any account can run `proof`, unless the distribution's service sets a narrower umask (not yet checked on a real guest). Guest parameters come from `.kvp_pool_3`. `proof status` reports a missing daemon (`hv_kvp_daemon` or `hypervkvpd`).
- **Windows**: `HKLM\SOFTWARE\Microsoft\Virtual Machine\External`, and guest parameters from `...\Guest\Parameters`. This needs the Data Exchange integration service enabled for the VM. The key grants read to Authenticated Users, so any account can run `proof`, and so any account can read the host token (Design.md gotcha 7).

`VirtualMachineId`, `VirtualMachineName` and `PhysicalHostName` from the guest parameters appear in `status` and in messages. They are not trusted. `status` warns if `VirtualMachineId` differs from the host token's `sub` (the bare VM ID), which a copied VM can show until its host writes its own token.

To keep a token file fresh, run `proof token --out` on a timer well inside the issued lifetime (5 minutes by default). For example, with systemd:

```ini
# /etc/systemd/system/proof-token.service
[Service]
Type=oneshot
ExecStart=/usr/bin/proof token --audience sts.example --out /run/proof/token --wait 60

# /etc/systemd/system/proof-token.timer
[Timer]
OnBootSec=0
OnUnitActiveSec=2min
[Install]
WantedBy=timers.target
```

On Windows, a scheduled task that repeats every 2 minutes does the same job.

Install it from a package:

- **Windows**: `msiexec /i proof-1.2.3-x64.msi /qn` installs `C:\Program Files\Proof\proof.exe` and puts that folder on the machine `PATH` (new processes see it). The MSI does not write `config.json`.
- **Debian and Ubuntu**: `apt-get install ./proof_1.2.3_amd64.deb` installs `/usr/bin/proof` and an empty `/etc/proof`. It depends on `libssl` and `ca-certificates`, and recommends `hyperv-daemons` (Debian) or `linux-cloud-tools-virtual` (Ubuntu) for `hv_kvp_daemon`. The image supplies `config.json`.

The packages hold a self-contained, trimmed single file (about 15 MB on win-x64 and 17 MB on linux-x64), which the project builds whenever a runtime is given. Globalization is invariant, so Linux images need no ICU. TLS still needs OpenSSL (`libssl`), as for any .NET app:

```sh
dotnet publish src/Proof.Client -c Release -r linux-x64
dotnet publish src/Proof.Client -c Release -r win-x64
```

The project has the AOT analyzers on, and `-p:PublishAot=true -p:PublishSingleFile=false` compiles without warnings. Linking a NativeAOT build needs the platform toolchain on a machine of the target OS, and that build has not been tried.

## Instance metadata

Proof also serves an EC2-style instance metadata API, for cloud-init and Cloudbase-Init. The data is YAML in the VM's Hyper-V notes. It reaches the VM over a Hyper-V socket, so it needs no network, and `proof-metadata` in the VM serves it on `127.0.0.1:8169`. The hypervisor names the calling VM, so a VM cannot ask for another's data. The issuer has no part in it. See [Design.md section 16](docs/Design.md).

### On the VM: the notes

A VM uses this only if its image has `proof-metadata` installed and its cloud-init or Cloudbase-Init pointed at it, so that configuration is the opt-in. Add a block to the VM's notes, in Hyper-V Manager or with `Set-VM -Notes`, to give it data. The rest of the notes stay yours:

```yaml
Owned by the web team.
#proof-metadata-begin
meta-data:
  local-hostname: web01
  public-keys:
    - ssh-ed25519 AAAA... me@example
user-data: !sensitive |
  #cloud-config
  password: hunter2
  phone_home:
    url: http://127.0.0.1:8169/proof/v1/provisioning/complete
    post: [instance_id]
#proof-metadata-end
```

- The marker lines start at the first column. The only top-level keys are `meta-data`, `user-data` and `provisioning`.
- `!sensitive` marks a value to clear when provisioning finishes. The tag is not part of the value. Any single value can carry it, in `meta-data` or `user-data`.
- `provisioning` is `pending` (the default), `complete` or `failed`. To provision again, set it back to `pending` and supply any sensitive values again.
- `instance-id` comes from the VM's BIOS GUID and cannot be set here. `local-hostname` defaults to the VM's name, if that can be a hostname.
- Hyper-V holds at most 32,768 characters of notes, block included, and refuses more.

**Write the block before first boot.** A VM with no block gets its instance ID and hostname, and cloud-init provisions with those and records the instance as done. A block added afterwards does nothing until you run `new-instance-id` below, and any sensitive values in it wait in the notes and the API until then. If such a VM reports that it finished, the host adds the least block that records it to the end of the notes:

```yaml
#proof-metadata-begin
provisioning: { status: complete, at: "2026-10-31T22:08:10Z", instance-id: i-6449418dc2894e1398caa391ec73b1e9 }
#proof-metadata-end
```

Set `UnsetMetadataHandler` to `404` in `refresher.json` to refuse VMs with no block instead. Cloud-init retries a 404 until its `max_wait`, so they boot that much later.

When the guest reports that provisioning finished, the host replaces each sensitive value in the notes with `!cleared "<time>"`, records the status, and keeps your comments and layout. A block that cannot be used serves nothing, not even the basic data, and `proof-refresher` logs why: otherwise cloud-init would finish without your user data, and fixing the typo would not run it again. Check one from the host:

```powershell
& "C:\Program Files\Proof\proof-refresher.exe" metadata show --vm web01             # what it would serve; never prints sensitive values
& "C:\Program Files\Proof\proof-refresher.exe" metadata finish --vm web01 --result complete   # clear now, if the guest will never report
```

**Clones.** A copy that keeps the BIOS GUID is the same instance to cloud-init, and is not provisioned again. `Import-VM -Copy` keeps it, even with `-GenerateNewId`, which changes only the VM ID. To make a copy a new instance, give it a new BIOS GUID while it is off, and set `provisioning` back to `pending` if the source had finished:

```powershell
& "C:\Program Files\Proof\proof-refresher.exe" metadata new-instance-id --vm web02
```

### In the image: cloud-init

`proof-metadata` starts before cloud-init, from the package. Tell cloud-init where it is, in `/etc/cloud/cloud.cfg.d/90-proof.cfg`. Listing Ec2 as the only datasource matters: `ds-identify` otherwise drops it on an unknown platform.

```yaml
datasource_list: [Ec2, None]
datasource:
  Ec2:
    metadata_urls: ["http://127.0.0.1:8169"]
    strict_id: false
    max_wait: 60
```

`max_wait` is how long cloud-init keeps asking when it gets a 503, or a 404 under `UnsetMetadataHandler: 404`. Keep it long enough for a busy host.

Have the user data report the end of provisioning with `phone_home`, as above. Leave `network` out of `meta-data` unless it has `interfaces.macs`: cloud-init then uses its fallback network configuration. The image also needs the `hv_sock` kernel module, which the package loads at boot. On Ubuntu's generic kernels it is in `linux-modules-extra`.

### In the image: Cloudbase-Init

In `cloudbase-init.conf`:

```ini
[DEFAULT]
metadata_services=cloudbaseinit.metadata.services.ec2service.EC2Service

[ec2]
metadata_base_url=http://127.0.0.1:8169/
```

Cloudbase-Init has no `phone_home`, so end the user data with the report:

```powershell
#ps1_sysnative
# ... provisioning ...
Invoke-RestMethod -Method Post http://127.0.0.1:8169/proof/v1/provisioning/complete
```

### What any local program can do

As on EC2, any program in the VM can read the API, including sensitive values until they are cleared, and can report provisioning finished. `curl http://127.0.0.1:8169/latest/meta-data/` shows the tree. A 503 means the host cannot be reached or cannot serve it, and the host's log says why. `GET /proof/v1/provisioning` shows the status, which is `none` with no block.

Sensitive values are plain text in the notes until cleared, readable by anyone who may read the VM's settings. Clearing may not reach checkpoints, which hold their own copy of a VM's settings, so avoid checkpointing a VM that holds secrets. In a PowerShell session that has already read the VM, `Get-VM` can show the old notes; a new session shows what the host holds.

### Checking on a real VM

`installer/Test-VmNotes.ps1`, elevated, checks the notes and BIOS GUID against real Hyper-V with a throwaway VM that is never started. For the whole path, on a host with the refresher installed: add the block above to a VM with the `proof` package, then in the VM:

```sh
curl http://127.0.0.1:8169/latest/meta-data/instance-id
curl http://127.0.0.1:8169/latest/user-data
curl -X POST http://127.0.0.1:8169/proof/v1/provisioning/complete
```

The notes should then show `!cleared` and the status.

## Status

- `Proof.Shared`: claim names, token types, host-token policy and key helpers (JWK and RFC 7638 `kid`).
- `Proof.Issuer`: implemented. Token exchange, allowlist loading and reload, discovery, JWKS, health, rate limits and metrics (`Proof.Issuer` meter), with the section 12 negative tests.
- `Proof.Refresher`: implemented. Host key management, host token signing, KVP writes over WMI, the refresh loop, metrics, and the `key` and `once` commands. Tested end to end on a Windows Server 2025 Hyper-V host against the issuer.
- `Proof.Client`: implemented. KVP reads on Linux (pool files) and Windows (registry), token exchange, token files, `token` and `status`. Linux pool reading was tested against synthetic pool files with a competing fcntl lock, not yet against a real `hv_kvp_daemon`. The Windows registry path was checked on a Hyper-V guest whose host has no refresher. No exchange has run end to end on a real VM yet.
- Instance metadata: tested end to end on Windows Server 2025 with a Debian 12 guest and cloud-init 22.4.2, with no network adapter (Design.md 16.7). Not yet tested: a Windows guest, Cloudbase-Init, a live migration, and the .deb's install scripts.
- Packaging: both MSIs were installed, upgraded, repaired, refused a downgrade and uninstalled on Windows Server 2025, including the refresher MSI's refusals without settings or host key, and the refresher writing KVP to a VM as its virtual account. The .deb, the container image and the workflow have not run yet; CI runs them on the first push.

## License

[Apache License 2.0](LICENSE).
