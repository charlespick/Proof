# Setting up the client

The client lives inside your VM images. It has two parts:

- **`proof`**, a command that gets a JWT for the service you want to talk to.
- **`proof-metadata`**, a small service that lets cloud-init or Cloudbase-Init read their configuration from the Hyper-V host.

Neither contains a secret. Every VM built from the same image gets its own identity from the host it runs on.

## Install

Download a package from the [releases page](https://github.com/charlespick/Proof/releases) and install it while building your image.

**Debian and Ubuntu**

```sh
apt-get install ./proof_<version>_amd64.deb
```

This installs `/usr/bin/proof`, the `proof-metadata` service, and an empty `/etc/proof`. It also pulls in `hyperv-daemons` (Debian) or `linux-cloud-tools-virtual` (Ubuntu), which provide `hv_kvp_daemon`, the service that receives the host's token. Make sure that daemon is enabled in your image.

**Windows**

```powershell
msiexec /i proof-<version>-x64.msi /qn
```

This installs `C:\Program Files\Proof\proof.exe`, adds it to the machine `PATH`, and installs the `proof-metadata` service. The VM needs the Data Exchange integration service enabled in Hyper-V.

## Configure

The client needs to know one thing: where your issuer is. Put it in `/etc/proof/config.json` on Linux or `%ProgramData%\Proof\config.json` on Windows, as part of your image build:

```json
{ "IssuerUrl": "https://id.example.com" }
```

| Setting | Default | Meaning |
| ------- | ------- | ------- |
| `IssuerUrl` | required | Exactly the issuer's URL. It is baked into the image and never learned from the host |
| `TokenEndpoint` | `IssuerUrl` + `/token` | Set this if VMs reach `/token` at a different, internal address |
| `CaBundlePath` | the system trust store | A PEM file of CA certificates to trust for the issuer, if it uses a private CA |

The VM must trust the certificate on your issuer URL. For a private CA, either add it to the image's trust store or point `CaBundlePath` at it.

## Getting a token

```sh
proof token --audience my-service
```

This prints a JWT for `my-service`, which you present to that service as you would any bearer token. The audience is whatever name the service expects in the token's `aud` claim.

Some tools expect a token file instead, for example cloud SDKs that support workload identity federation. Write one and keep it fresh:

```sh
proof token --audience sts.example.com --out /run/proof/token
```

Tokens last five minutes by default, so run that on a timer. With systemd:

```ini
# /etc/systemd/system/proof-token.service
[Service]
Type=oneshot
ExecStart=/usr/bin/proof token --audience sts.example.com --out /run/proof/token --wait 60

# /etc/systemd/system/proof-token.timer
[Timer]
OnBootSec=0
OnUnitActiveSec=2min
[Install]
WantedBy=timers.target
```

On Windows, a scheduled task that repeats every two minutes does the same job.

### Options

| Option | Meaning |
| ------ | ------- |
| `--audience <name>` | Required. The service the token is for |
| `--out <path>` | Write the token to a file instead of printing it. The file is replaced atomically, so readers never see a partial token |
| `--wait <seconds>` | Wait for the host's token to arrive. Useful early in boot, since a VM can start before the host has written one |
| `--config <path>` | Use a different settings file |

Exit codes: `0` success, `1` failure, `2` bad usage, `3` the host has not written a token yet (retry shortly).

### Troubleshooting

```sh
proof status
```

shows whether the host's token has arrived and whether it is valid, without printing it. It reports a missing `hv_kvp_daemon` on Linux, and common problems such as an expired token or a clock that is behind the host's. When the issuer refuses a request, `proof` explains what it can see; the issuer's own log has the definitive reason.

If `proof` reports no host token, check that the refresher is running on the host, that the host's key is on the issuer's allowlist, and that the VM has Data Exchange enabled.

## Instance metadata

`proof-metadata` listens on `127.0.0.1:8169` inside the VM and serves an EC2-compatible metadata API. It fetches the data from the host over a Hyper-V socket, so it works before the VM has any network. It starts before cloud-init and needs no configuration. You write the data into the VM's notes on the host; see the [refresher](refresher.md#instance-metadata) page.

Linux images also need the `hv_sock` kernel module, which the package loads at boot. On Ubuntu's generic kernels it comes from `linux-modules-extra`.

### cloud-init

Tell cloud-init to use it in `/etc/cloud/cloud.cfg.d/90-proof.cfg`:

```yaml
datasource_list: [Ec2, None]
datasource:
  Ec2:
    metadata_urls: ["http://127.0.0.1:8169"]
    strict_id: false
    max_wait: 60
```

Listing `Ec2` first is important. Cloud-init's platform detection would otherwise skip it on Hyper-V.

Have your user data report when it is done, so the host can clear any secrets it was given:

```yaml
#cloud-config
phone_home:
  url: http://127.0.0.1:8169/proof/v1/provisioning/complete
  post: [instance_id]
```

### Cloudbase-Init

In `cloudbase-init.conf`:

```ini
[DEFAULT]
metadata_services=cloudbaseinit.metadata.services.ec2service.EC2Service

[ec2]
metadata_base_url=http://127.0.0.1:8169/
```

Cloudbase-Init has no equivalent of `phone_home`, so finish your user data with a report:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8169/proof/v1/provisioning/complete
```

### Trying it

In a VM whose notes contain a metadata block:

```sh
curl http://127.0.0.1:8169/latest/meta-data/instance-id
curl http://127.0.0.1:8169/latest/user-data
```

A `503` means the host can't be reached or can't serve this VM yet, and the refresher's log on the host says why. Clients retry it.

Before you rely on any of this, read [Security](security.md). In particular, remember that any program running inside the VM can read the metadata, just as on EC2.
