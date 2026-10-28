# Proof

Proof lets a Hyper-V VM prove which VM it is to on-premises services. The Hyper-V host signs a short-lived token and writes it into the VM over KVP (Hyper-V Data Exchange). The VM trades that token for audience-specific JWTs, which consumers verify against the issuer's published keys without calling the host or a database.

Proof does authentication only. Consumers decide what an identity may do. See [Design.md](docs/Design.md) for the full specification.

## Components

| Project | Path | Role |
| ------- | ---- | ---- |
| `Proof.Refresher` | `src/Proof.Refresher` | Windows service on each Hyper-V host. Signs a host token for each VM and writes it into that VM's KVP pool about every 5 minutes. |
| `Proof.Issuer` | `src/Proof.Issuer` | ASP.NET Core service on Kubernetes. Verifies host tokens against the host-key allowlist, mints audience-specific JWTs at `/token` (RFC 8693), and serves the OIDC discovery document and JWKS. |
| `Proof.Client` | `src/Proof.Client` | The `proof` command on every VM image. Reads the host token from KVP, calls the issuer, and prints or writes the issued JWT. |
| `Proof.Shared` | `src/Proof.Shared` | Class library shared by the refresher and issuer: claim names, token types and validation settings. |

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

Requires the .NET SDK (10.0 or later). Tests use [xUnit v3](https://xunit.net/).

```sh
dotnet build Proof.slnx
dotnet test --solution Proof.slnx
```

## Status

Scaffold only. The projects are template stubs. The only libraries chosen so far are xUnit v3 for tests and `Microsoft.Extensions.Hosting.WindowsServices` for the refresher.
