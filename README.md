# Proof

Proof lets a Hyper-V VM prove which VM it is to on-premises services. The Hyper-V host signs a short-lived token and writes it into the VM over KVP (Hyper-V Data Exchange). The VM trades that token for audience-specific JWTs, which consumers verify against the issuer's published keys without calling the host or a database.

Proof does authentication only. Consumers decide what an identity may do. See [Design.md](docs/Design.md) for the full specification.

## Components

| Project | Path | Role |
| ------- | ---- | ---- |
| `Proof.Refresher` | `src/Proof.Refresher` | Windows service on each Hyper-V host. Signs a host token for each VM and writes it into that VM's KVP pool about every 5 minutes. |
| `Proof.Issuer` | `src/Proof.Issuer` | ASP.NET Core service on Kubernetes. Verifies host tokens against the host-key allowlist, mints audience-specific JWTs at `/token` (RFC 8693), and serves the OIDC discovery document and JWKS. |
| `Proof.Client` | `src/Proof.Client` | The `proof` command on every VM image. Reads the host token from KVP, calls the issuer, and prints or writes the issued JWT. |
| `Proof.Shared` | `src/Proof.Shared` | Class library shared by all three programs: claim names, token types, validation settings and KVP limits. |

## Repository layout

```
Proof.slnx
docs/
  Design.md
src/
  Proof.Shared/
  Proof.Issuer/
  Proof.Refresher/
  Proof.Client/
tests/
  Proof.Tests/
```

## Building and testing

Requires the .NET SDK (10.0 or later). Tests use [xUnit v3](https://xunit.net/). NuGet versions are pinned in each project's `packages.lock.json`.

```sh
dotnet build Proof.slnx
dotnet test --solution Proof.slnx
```

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
| `EnforceClusterScope` | `false` | Require a host token's `cluster` to match its host's allowlist entry |
| `TokenRequestsPerMinute` | `60` | Rate limit per source address on `/token` |

Endpoints: `POST /token`, `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json`, `GET /healthz/live`, and `GET /healthz/ready` (ready once an allowlist has loaded).

To try it locally:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out signing-key.pem
Proof__IssuerUrl=https://id.example Proof__AllowlistPath=allowlist.yaml Proof__SigningKeyPath=signing-key.pem dotnet run --project src/Proof.Issuer
```

Behind an ingress, the rate limiter sees the client address only if forwarded headers are trusted, for example with `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` when only the ingress can reach the pod. The signing key is read at startup, so a rotation takes effect when the pods roll.

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

Set up a host (elevated):

```powershell
New-Item -ItemType Directory -Force $env:ProgramData\Proof
'{ "Proof": { "IssuerUrl": "https://id.corp.example", "Cluster": "prod" } }' | Set-Content $env:ProgramData\Proof\refresher.json
proof-refresher key create          # prints the allowlist entry to add by pull request
proof-refresher once                # write to every running VM now and report
sc.exe create proof-refresher binPath= "C:\Program Files\Proof\proof-refresher.exe" start= auto
sc.exe start proof-refresher
```

`proof-refresher key show` prints the entry again, along with who may use the key. To run the service under its virtual account instead of Local System, install it first, then `key create --grant "NT SERVICE\proof-refresher"`, then `sc.exe config proof-refresher obj= "NT SERVICE\proof-refresher"`. The account also needs Hyper-V rights (Design.md 14, item 6).

Publish as a self-contained single file (NativeAOT does not work, because WMI needs built-in COM):

```sh
dotnet publish src/Proof.Refresher -c Release -r win-x64 --self-contained -p:PublishSingleFile=true
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

Where the client reads KVP:

- **Linux**: `/var/lib/hyperv/.kvp_pool_0`, the External pool file `hv_kvp_daemon` keeps (512-byte key and 2048-byte value records). Reads take an fcntl read lock, so they never see the daemon halfway through a rewrite. Upstream, the daemon creates the file mode 0644, so any account can run `proof`, unless the distribution's service sets a narrower umask (not yet checked on a real guest). Guest parameters come from `.kvp_pool_3`. `proof status` reports a missing daemon (`hv_kvp_daemon` or `hypervkvpd`).
- **Windows**: `HKLM\SOFTWARE\Microsoft\Virtual Machine\External`, and guest parameters from `...\Guest\Parameters`. This needs the Data Exchange integration service enabled for the VM. The key grants read to Authenticated Users, so any account can run `proof`, and so any account can read the host token (Design.md gotcha 7).

`VirtualMachineId`, `VirtualMachineName` and `PhysicalHostName` from the guest parameters appear in `status` and in messages. They are not trusted. `status` warns if `VirtualMachineId` differs from the token's `sub`, which a copied VM can show until its host writes its own token.

To keep a token file fresh, run `proof token --out` on a timer well inside the issued lifetime (5 minutes by default). For example, with systemd:

```ini
# /etc/systemd/system/proof-token.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/proof token --audience sts.example --out /run/proof/token --wait 60

# /etc/systemd/system/proof-token.timer
[Timer]
OnBootSec=0
OnUnitActiveSec=2min
[Install]
WantedBy=timers.target
```

On Windows, a scheduled task that repeats every 2 minutes does the same job.

Publish as a self-contained, trimmed single file (about 15 MB on win-x64 and 17 MB on linux-x64). Globalization is invariant, so Linux images need no ICU. TLS still needs OpenSSL (`libssl`), as for any .NET app:

```sh
dotnet publish src/Proof.Client -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true -p:PublishTrimmed=true
dotnet publish src/Proof.Client -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -p:PublishTrimmed=true
```

The project has the AOT analyzers on, and `-p:PublishAot=true` compiles without warnings. Linking a NativeAOT build needs the platform toolchain on a machine of the target OS, and that build has not been tried.

## Status

- `Proof.Shared`: claim names, token types, host-token policy and key helpers (JWK and RFC 7638 `kid`).
- `Proof.Issuer`: implemented. Token exchange, allowlist loading and reload, discovery, JWKS, health, rate limits and metrics (`Proof.Issuer` meter), with the section 12 negative tests.
- `Proof.Refresher`: implemented. Host key management, host token signing, KVP writes over WMI, the refresh loop, metrics, and the `key` and `once` commands. Tested end to end on a Windows Server 2025 Hyper-V host against the issuer.
- `Proof.Client`: implemented. KVP reads on Linux (pool files) and Windows (registry), token exchange, token files, `token` and `status`. Linux pool reading was tested against synthetic pool files with a competing fcntl lock, not yet against a real `hv_kvp_daemon`. The Windows registry path was checked on a Hyper-V guest whose host has no refresher. No exchange has run end to end on a real VM yet.
