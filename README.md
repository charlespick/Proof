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

## Status

- `Proof.Shared`: claim names, token types, host-token policy and key helpers (JWK and RFC 7638 `kid`).
- `Proof.Issuer`: implemented. Token exchange, allowlist loading and reload, discovery, JWKS, health, rate limits and metrics (`Proof.Issuer` meter), with the section 12 negative tests.
- `Proof.Refresher` and `Proof.Client`: template stubs.
