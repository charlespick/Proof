# Contributing

Thanks for helping with Proof. Issues and pull requests are welcome.

## Building and testing

Proof needs the .NET SDK version pinned in `global.json`. NuGet versions are pinned in each project's `packages.lock.json`, and CI restores in locked mode. After changing a package reference, run `dotnet restore Proof.slnx --force-evaluate` and commit the updated lock files. To move to a newer SDK, change `global.json` and the SDK image in the Dockerfile together, then regenerate the lock files.

```sh
dotnet build Proof.slnx
dotnet test --solution Proof.slnx
```

Tests use [xUnit v3](https://xunit.net/).

## Repository layout

```
src/
  Proof.Shared/       claim names, token types and the host-to-VM socket protocol
  Proof.Issuer/       the issuer (includes the Dockerfile)
  Proof.Refresher/    the Windows service on each Hyper-V host
  Proof.Client/       the `proof` command
  Proof.Metadata/     the `proof-metadata` service
tests/Proof.Tests/
installer/            Windows MSIs (WiX 5)
packaging/debian/     the Linux client .deb
build/                version calculation
docs/                 user documentation
```

## Packages and releases

| Package | Built by |
| ------- | -------- |
| `proof-refresher-<version>-x64.msi` | `dotnet build installer/Proof.Refresher.Installer/Proof.Refresher.Installer.wixproj -c Release` (Windows) |
| `proof-<version>-x64.msi` | `dotnet build installer/Proof.Client.Installer/Proof.Client.Installer.wixproj -c Release` (Windows) |
| `proof_<version>_amd64.deb` | `dotnet publish` of `src/Proof.Client` and `src/Proof.Metadata` with `-c Release -r linux-x64` into one folder, then `packaging/debian/build-deb.sh` |
| `ghcr.io/charlespick/proof-issuer:<version>` | `docker build -f src/Proof.Issuer/Dockerfile .` |

`installer/Test-Installers.ps1` installs and removes both MSIs and checks what they do. It changes the machine, so run it on a throwaway one.

[CI](.github/workflows/ci.yml) tests on Windows and Linux and builds every package on every push. A `v*` tag on a commit on `main` also publishes a GitHub release with the MSIs, the `.deb` and `SHA256SUMS`, and pushes the image.

## Versions

Versions come from the nearest git tag, read in [build/Version.targets](build/Version.targets). Tag releases `vMAJOR.MINOR.PATCH`, with an optional dotted prerelease such as `v1.3.0-rc.1`. Commits after a tag build as a prerelease of the next patch.

| HEAD | Version | MSI ProductVersion | .deb version |
| ---- | ------- | ------------------ | ------------ |
| at `v1.2.3` | `1.2.3` | `1.2.3` | `1.2.3` |
| 4 commits after `v1.2.3` | `1.2.4-0.dev.4` | `1.2.4` | `1.2.4~0.dev.4` |
| at `v1.3.0-rc.1` | `1.3.0-rc.1` | `1.3.0` | `1.3.0~rc.1` |

Windows Installer compares only the three-part ProductVersion, so builds of one version replace each other in either direction, and going back to an older version means uninstalling first. A build outside a git clone needs `-p:ProofVersion=<version>`; the container build takes `--build-arg VERSION=<version>`.
