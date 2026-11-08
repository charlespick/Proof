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

Exit codes: `0` success, `1` failure, `2` bad usage, `3` the host has not written a token (retry shortly, or see below).

### Troubleshooting

```sh
proof status
```

shows whether the host's token has arrived and whether it is valid, without printing it. It also shows the identity the token carries: the subject the issuer will put in `sub`, the tenant, the assigned ID and the security tags. It reports a missing `hv_kvp_daemon` on Linux, and common problems such as an expired token, a clock that is behind the host's, or a token from a host whose refresher is older than the issuer. When the issuer refuses a request, `proof` explains what it can see; the issuer's own log has the definitive reason.

If `proof` reports no host token, first check that the VM's notes have an [`identity:` block](refresher.md#vm-identity). The host writes a token only for VMs that have one, so without it there is no token by design. On the host, `proof-refresher metadata show --vm <name>` shows the identity it reads or says why the block can't be used. If the block is fine, check that the refresher is running on the host and that the VM has Data Exchange enabled.

## Instance metadata

`proof-metadata` listens on `127.0.0.1:8169` inside the VM and serves OpenStack's metadata API: `meta_data.json`, `user_data` and `network_data.json` under `/openstack/latest`. It fetches the data from the host over a Hyper-V socket, so it works before the VM has any network, and `network_data.json` can give the VM a static address with no DHCP anywhere. It starts before cloud-init and needs no configuration. You write the data into the VM's notes on the host; see the [refresher](refresher.md#instance-metadata) page.

Linux images also need the `hv_sock` kernel module, which the package loads at boot. On Ubuntu's generic kernels it comes from `linux-modules-extra`.

Only the `latest` version is served. Cloudbase-Init sends the password it sets back to the metadata service if the dated version `2013-04-04` exists, and nothing a guest sends is ever stored.

### cloud-init

The package includes a cloud-init data source for it, `Proof`. Turn it on in `/etc/cloud/cloud.cfg.d/99-proof.cfg`:

```yaml
datasource_pkg_list: [proof_cloudinit]
datasource_list: [Proof]
```

- **List it alone.** With a single entry, cloud-init skips detecting the platform, and with no `None` after it, a VM that can't reach its host fails closed instead of booting unconfigured. This needs cloud-init 23.4 or later, as in Debian 13 and Ubuntu 24.04.
- It waits up to 2 minutes for the host. Settings go under `datasource: Proof:` and are cloud-init's usual `max_wait`, `timeout` and `retries`.

The data source is cloud-init's own OpenStack data source with two changes, both because the metadata is on loopback rather than on the network:

- **No DHCP.** OpenStack's takes a temporary DHCP lease before it reads the metadata. Proof's reads it in cloud-init's first stage, before the network starts, on any network, so the static configuration in `network_data.json` is in place when the network comes up. The first boot of a Debian 13 VM took about a minute and a half with or without DHCP on the network, against 4 minutes without DHCP for OpenStack's.
- **No EC2.** OpenStack's also reads EC2's metadata from `169.254.169.254`, which nothing answers on Hyper-V. Proof's doesn't, so nothing is sent to the default gateway, and `cloud-init status` isn't marked `degraded`.

Everything else, including how `network_data.json` becomes the network configuration, is cloud-init's. The links name each adapter by MAC address, so give the VM's adapters static MACs on the host.

Later boots reuse cloud-init's cache, so they keep the static address and don't need the host. Cloud-init reuses the cache only while the instance ID matches the VM's SMBIOS UUID, which it does unless you change the VM's BIOS GUID.

The data source builds on parts of cloud-init that aren't a stable interface, so boot a VM from each new image to check it, as for any image change. Cloud-init's OpenStack data source also reads Proof's metadata, with `datasource_list: [OpenStack]` and `metadata_urls: ["http://127.0.0.1:8169"]`, but with the DHCP and EC2 behavior above.

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
metadata_services=cloudbaseinit.metadata.services.httpservice.HttpService
plugins=cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin,cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin,cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin,cloudbaseinit.plugins.windows.extendvolumes.ExtendVolumesPlugin,cloudbaseinit.plugins.common.userdata.UserDataPlugin
username=Administrator
inject_user_password=true
first_logon_behaviour=no

[openstack]
metadata_base_url=http://127.0.0.1:8169/
add_metadata_private_ip_route=false
```

`NetworkConfigPlugin` applies `network_data.json` before `UserDataPlugin` runs your user data, so the network is up before, for example, a domain join. With `inject_user_password`, `SetUserPasswordPlugin` sets the Administrator password from `admin_pass` in the meta-data. This configuration has not yet been tried on a Windows guest.

Cloudbase-Init has no equivalent of `phone_home`, so finish your user data with a report:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8169/proof/v1/provisioning/complete
```

### Trying it

In a VM whose notes contain a metadata block:

```sh
curl http://127.0.0.1:8169/openstack/latest/meta_data.json
curl http://127.0.0.1:8169/openstack/latest/network_data.json
curl http://127.0.0.1:8169/openstack/latest/user_data
```

A `503` means the host can't be reached or can't serve this VM yet, and the refresher's log on the host says why. Clients retry it.

Before you rely on any of this, read [Security](security.md). In particular, remember that any program running inside the VM can read the metadata, just as on EC2.
