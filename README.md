# Proof

Proof is an OIDC-compliant workload identity provider and instance metadata service for Hyper-V. It gives every VM a verifiable identity without passwords, API keys or any secret baked into an image, and it provisions VMs with cloud-init or Cloudbase-Init the way a public cloud does.

- **Workload identity.** A VM asks for a short-lived JWT and presents it to any service that speaks OIDC: Kubernetes, Vault, step-ca, Puppet, or a cloud provider through workload identity federation. The service checks the signature against Proof's published keys, so it never calls back to the host.
- **Instance metadata.** Cloud-init and Cloudbase-Init read their hostname, SSH keys and user data from an EC2-compatible endpoint inside the VM. The data comes from the VM's Hyper-V notes and travels over a Hyper-V socket, so the VM needs no network to be provisioned.

Proof does authentication only. It tells your services *which VM* is calling; what that VM may do is up to them.

## How it works

Proof has three pieces:

| Piece | Where it runs | What it does |
| ----- | ------------- | ------------ |
| **Issuer** | A container, ideally on Kubernetes | Verifies requests from VMs and mints JWTs. Publishes the OIDC discovery document and signing keys. |
| **Refresher** | Each Hyper-V host, as a Windows service | Vouches for the VMs it runs by handing each one a short-lived signed token. Also serves instance metadata to its VMs. |
| **Client** | Every VM image, Linux or Windows | The `proof` command trades the host's token for a JWT. The `proof-metadata` service presents instance metadata to cloud-init. |

1. The **refresher** on the Hyper-V host signs a short-lived token for each VM and writes it into the VM.
2. Inside the VM, **`proof`** sends that token to the **issuer**.
3. The issuer checks that the host is on its allowlist and returns a JWT for the service the VM named.
4. The VM presents the JWT to that service, which verifies it against the issuer's published keys.

## Getting started

Set the pieces up in this order:

1. **[Deploy the issuer](docs/issuer.md).** Pick its URL, create a signing key and an empty host allowlist, and run the container.
2. **[Install the refresher](docs/refresher.md)** on each Hyper-V host, then add the host's public key to the issuer's allowlist.
3. **[Put the client in your VM images](docs/client.md)**, point it at the issuer, and request your first token.
4. **[Read about security](docs/security.md)** before you rely on it: what each part trusts, what a process inside a VM can do, and how Proof compares to the EC2 metadata service.

Packages are on the [releases page](https://github.com/charlespick/Proof/releases): MSIs for the refresher and the Windows client, a `.deb` for the Linux client, and the issuer image at `ghcr.io/charlespick/proof-issuer`.

## Status

Proof is in beta. The refresher and instance metadata have been tested on Windows Server 2025 Hyper-V hosts, with a Debian 12 guest and cloud-init. Windows guests, Cloudbase-Init and the full token flow on a production-style VM have had less testing. Reports and fixes are welcome.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test and release.

## License

[Apache License 2.0](LICENSE).
