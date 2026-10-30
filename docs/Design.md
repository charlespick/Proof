# Proof: Design Specification (Hyper-V)

Oct 27, 2026 · @Charles Pickering

## 1. Purpose and scope

Proof lets a Hyper-V VM prove which VM it is to on-premises services, using a short-lived token that its Hyper-V host writes into the VM over KVP (Hyper-V Data Exchange). Consumers verify the result without calling the host or a database.

**In scope**

- Authenticating Linux and Windows VMs on Hyper-V hosts.
- Intended consumers: Puppet, step-ca and MicroK8s. Integrating them is outside Proof.
- OIDC-compatible output (discovery document, JWKS, audience-specific JWTs) so cloud workload identity federation can be added later.

**Non-goals**

- Authorization: no roles, labels or policy. Consumers decide what an identity may do.
- Revocation machinery, proof of possession, or replay protection beyond short token lifetimes.
- SPIRE or any other identity framework, and emulation of AWS, Azure or GCP metadata endpoints.
- VM creation, the management UI, and the consumer integrations themselves (Puppet, step-ca, MicroK8s). Those are separate work that will consume Proof's identity.

**Principles**

1. No custom cryptography. Signing, verification, key encoding and claim checks come from maintained libraries.
2. Authentication only.
3. Stateless verification: no database. Trust comes from public keys on an allowlist.
4. One source of host trust: the allowlist lives on the issuer and nowhere else.
5. Few components and one language.
6. Short lifetimes instead of revocation features.

## 2. Decision log

Thirteen decisions are settled or proposed. "Decided" means you chose it in our discussion. "Proposed" means I recommend it and you have not confirmed it.

| # | Decision | Reason | Status |
| --- | --- | --- | --- |
| 1 | Authentication only: no roles, labels or authorization policy | The issuer says who a VM is; consumers decide what it may do | Decided |
| 2 | Subject is the Hyper-V VM ID, scoped by the signing host's failover cluster, or by the host when it is in none: `cluster:<cluster>/<vmid>` or `host:<host>/<vmid>`, taken from the allowlist | Names can repeat and can be renamed; the VM ID cannot. But VM IDs are unique only within a cluster or a standalone host: an import or a restore elsewhere keeps the ID | Decided |
| 3 | Host trust is one layer: each host has its own key, and the issuer holds an allowlist of host public keys. Removing a key ends trust in it | No CA hierarchy; revocation is the allowlist edit | Decided |
| 4 | Token lifetime is the only leak and replay control. No proof of possession, no replay counter | Short lifetimes already bound the exposure | Decided |
| 5 | No SPIRE. Build the issuer on JOSE libraries | Less to run; libraries do the cryptography | Decided |
| 6 | Host refresher is written in C# | Needs WMI and Windows key storage | Decided |
| 7 | Audience-specific tokens are requested on demand through RFC 8693 token exchange. The KVP token has one fixed audience (the issuer) | An OIDC audience cannot be minted ahead of time | Decided |
| 8 | No metadata service, cloud-init or Cloudbase-Init. The host writes the token over KVP and a small VM client fetches JWTs | Smaller moving parts | Decided |
| 9 | Issuer and VM client are also C#/.NET | One language and one JOSE library family across all components; garbage-collected and compiled; runs on Linux | Proposed |
| 10 | ES256 (ECDSA P-256) for host tokens and issued tokens; RS256 only if a federation target requires it | Small signatures, built into Windows CNG, accepted by GCP | Proposed |
| 11 | Verification logic is not a Proof deliverable: consumers verify issued JWTs with standard OIDC and JWT libraries, as they would any OIDC token | OIDC is the common standard, so consumers use the validation they already have | Proposed |
| 12 | The issuer runs on Linux as a Kubernetes Deployment, and its configuration and host allowlist are delivered by your existing GitOps | Fits your platform, and changes go through the review you already have | Decided |
| 13 | Host keys are non-exportable CNG machine keys in the Microsoft Software Key Storage Provider. No TPM | Every Windows host has it; no hardware dependency or per-host variation | Decided |

## 3. Architecture

The host signs a token into each VM's KVP, and the VM trades that token for audience-specific JWTs that consumers verify against the issuer's public keys.

&#91;embedded content: architecture · 4 groups, 5 numbered flows\]

1. The refresher signs a host token with the host key and writes it to the VM's KVP pool as soon as the VM starts or migrates in, and again about every 5 minutes. This is the only step that runs without a request.
2. The VM client reads the token and sends it to the issuer, naming the audience it wants.
3. The issuer checks the token against the host allowlist and returns a JWT for that audience.
4. The VM presents the JWT to a consumer service.
5. Consumers verify the JWT against the issuer's published keys.

**Trust boundaries**

- Host to issuer: the allowlisted host key is the only root of trust.
- Issuer to consumers: the issuer's signing key, published in the JWKS.
- Inside a VM: anything that can read the KVP pool can read the host token. Its short life bounds the exposure.

## 4. Components and languages

Three programs are ours to write; Hyper-V stays as it is.

| Component | Runs on | Language | Responsibility |
| --- | --- | --- | --- |
| Host refresher (`proof-refresher`) | Each Hyper-V host, as a Windows service | C#/.NET | When a VM starts or migrates in, and about every 5 minutes for each running VM: sign a host token with the host key and write it into that VM's KVP External pool |
| Issuer (`proof-issuer`) | Kubernetes on Linux, as a Deployment with two replicas | C#/.NET, ASP.NET Core | Verify host tokens against the allowlist; mint audience-specific JWTs at `/token` (RFC 8693); serve the discovery document and JWKS |
| VM client (`proof`) | Every VM image, Linux and Windows | C#/.NET, self-contained single file | Read the host token from KVP; call the issuer; print or write the result |

**Notes**

- Publish every C# component as a self-contained single-file executable, so images need no .NET runtime. Verify size and startup time on your images.
- The refresher must run on the Hyper-V host. The issuer runs on Linux as a Kubernetes Deployment, shipped as a container image.
- Keep one small shared library for claim names, token types and validation settings, so the refresher and issuer cannot drift apart.
- Why C# for the issuer is in section 5.

**Command line**

- `proof token --audience <aud> [--out <path>]`: read the host token from KVP, call the issuer, and print the JWT or write it to a file. Run it on a timer with `--out` to keep a token file fresh for SDKs that read one (Azure and AWS SDKs read `AZURE_FEDERATED_TOKEN_FILE` and `AWS_WEB_IDENTITY_TOKEN_FILE`).
- `proof status`: show whether a host token is present and when it expires, without printing it. For troubleshooting.

## 5. Algorithms and libraries

Microsoft.IdentityModel and the .NET platform do all cryptographic work; our code only decides policy.

**Algorithms**

| Purpose | Algorithm | Why |
| --- | --- | --- |
| Host token signature | ES256 (ECDSA, P-256, SHA-256) | A 64-byte signature keeps the token small enough for one KVP value. P-256 is built into the CNG software key storage provider on every Windows host |
| Issued JWT signature | ES256 by default; RS256 only if a federation target rejects ES256 | GCP accepts RS256 or ES256. Entra and AWS acceptance is not confirmed (section 14) |
| Never accepted | `none`, HS256/384/512, any JWE | Not needed, and each widens the attack surface |

**Libraries (C#)**

- `Microsoft.IdentityModel.JsonWebTokens`: `JsonWebTokenHandler` creates and validates tokens. Use it, not the older `JwtSecurityTokenHandler`.
- `Microsoft.IdentityModel.Tokens`: `ECDsaSecurityKey`, `JsonWebKeySet`, and `TokenValidationParameters` with `ValidAlgorithms`, `ValidIssuer`, `ValidAudience`, `ValidateLifetime`, `ClockSkew` and `IssuerSigningKeys`.
- `System.Security.Cryptography.ECDsa` for keys. On Windows hosts, CNG holds the host key as a non-exportable machine key in the Microsoft Software Key Storage Provider.
- ASP.NET Core minimal APIs for the issuer's HTTP endpoints.

**Why C# for the issuer**

- The refresher must use WMI and CNG, so it is C# regardless. Using one JOSE library family to sign and to verify keeps validation behavior consistent.
- C# is garbage-collected, compiled, runs on Linux, and AI coding assistants handle it well, which meets your tiebreaker.
- Go (`go-jose`, `lestrrat-go/jwx`) has equally mature libraries. It loses only because it would add a second language.
- EdDSA would need extra work in Microsoft.IdentityModel (verify; one article treats it as an unsupported-algorithm path). That is another reason to choose ES256.

**What we do not write**

Base64url encoding, JWS assembly or parsing, signature creation or verification, expiry and not-before checks, JWK serialization and key thumbprints. If a task seems to need any of these, find the library call.

## 6. Protocol

Three messages carry everything: a host token written into KVP, a token exchange request to the issuer, and the issued JWT.

### 6.1 Host token

A compact JWS signed by the host key and written by the refresher.

Header: `{"alg":"ES256","typ":"proof-host+jwt","kid":"<host key thumbprint>"}`

| Claim | Value | Notes |
| --- | --- | --- |
| `iss` | Host ID from the allowlist | Must match the allowlist entry for `kid` |
| `aud` | The issuer URL | One fixed audience |
| `sub` | `cluster:<cluster>/<vmid>` if the signing key's allowlist entry has a cluster, otherwise `host:<host>/<vmid>`. The VM ID is the host token's `sub` | The issuer scopes it by the host's allowlist entry (6.4) |
| `vm_name` | VM name at signing time | Host-asserted and informational; never authorize on it |
| `cluster` | Cluster name | Present exactly when the host's allowlist entry has a cluster, and equal to it |
| `iat`, `nbf`, `exp` | Signing time; `exp` = `iat` + 20 minutes | Proposed. Refresh every 5 minutes |
| `jti` | Random 128-bit value | For logs only |

Example payload (illustrative values):

```json
{
  "iss": "hv-host-01",
  "aud": "https://id.corp.example",
  "sub": "11111111-2222-3333-4444-555555555555",
  "vm_name": "web01",
  "cluster": "prod",
  "iat": 1793000000,
  "nbf": 1793000000,
  "exp": 1793001200,
  "jti": "c1b2f6d0a7e44b0e9d3a5f1e8c7b6a49"
}
```

Measured: 527 characters in compact form with ES256, for a real VM on a Windows Server 2025 host with `cluster` and a 14-character `vm_name` (verified).

### 6.2 KVP layout

- The host writes into the External pool. In the guest that is `HKLM\SOFTWARE\Microsoft\Virtual Machine\External` on Windows and `/var/lib/hyperv/.kvp_pool_0` on Linux, where `hv_kvp_daemon` must be running.
- One key, `proof.v1.token`, holds the compact JWS.
- Limits: key up to 512 bytes, value up to 2048 bytes including the terminator, and the host side expects UTF-16. The host accepts a value of 1023 characters and refuses 1024 (verified on Windows Server 2025). A token never needs chunking: if one would exceed 1023 characters, the refresher leaves out `vm_name`, which is informational, and the refresher refuses at startup any settings whose fixed claims alone would not fit. A 100-character ASCII VM name (the Hyper-V maximum) still fits.
- Host API: `Msvm_VirtualSystemManagementService` methods `AddKvpItems`, `ModifyKvpItems` and `RemoveKvpItems`. Use Add for a new key and Modify for an existing one. Modify on a missing key fails with 32779 (not found) and Add on an existing key fails with 32773 (invalid parameter), so upsert is Modify, then Add on 32779 (verified). Both succeed for a VM that is off, running with no guest OS, or running with Data Exchange disabled, so a successful write does not prove the guest can read it (verified).
- Write timing: the refresher subscribes to WMI intrinsic events on `Msvm_ComputerSystem` for VMs entering Running (`EnabledState` 2), and runs a pass on each one. The Hyper-V provider raises these itself, without a `WITHIN` polling clause. It also raises many modification events that change nothing, so the refresher ignores modifications of a VM that was already running. A scheduled pass every 5 minutes renews tokens (any within 30 seconds of 5 minutes old) and covers missed events, and a failed write or a lost subscription brings the next pass forward to 30 seconds. Measured on Windows Server 2025 (verified):
  - A started VM had its token about 200 ms after `Start-VM` returned.
  - A live migration arrives on the destination as a creation in state 10 (starting) and then a change to 2 (running). Host KVP items travel with the VM, so it arrives carrying the source host's token, valid until it expires. The destination writes its own at once, which matters when a host is drained so its key can be removed.
  - For about 200 ms after reaching Running, a migrated VM refuses KVP writes with 32775 (invalid state), so the refresher retries that error for up to 15 seconds. The destination's token was in place about 260 ms after `Move-ClusterVirtualMachineRole` returned.
- Linux pool files hold fixed-size records: a 512-byte key followed by a 2048-byte value.
- The guest also sees host-pushed parameters (`VirtualMachineId`, `VirtualMachineName`, `PhysicalHostName`) in the `Guest\Parameters` pool. The client may log them as a sanity check. They are not trusted.

### 6.3 Token exchange (`POST /token`)

A program on the VM asks the issuer for a token for a named audience. The request follows RFC 8693 and is sent over TLS as `application/x-www-form-urlencoded`.

| Field | Value |
| --- | --- |
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | The host token read from KVP |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:jwt` |
| `requested_token_type` | `urn:ietf:params:oauth:token-type:jwt` |
| `audience` | The audience the consumer wants, such as `my-service`. This service requires it, and accepts one value in v1 |

There is no separate client credential: the signed host token is the credential. RFC 8693 notes that an unidentified client suits only limited conditions such as a closed network, so keep `/token` internal.

**Validation order on the issuer**

1. Reject a `subject_token` over 4 KB before parsing.
2. Header: `alg` is `ES256`, `typ` is `proof-host+jwt`, and `kid` is on the allowlist.
3. Verify the signature with that key.
4. `iss` equals the host recorded for that `kid`; `aud` equals the issuer URL.
5. `nbf` and `exp` hold within 2 minutes of skew, and `exp` minus `iat` is at most 30 minutes.
6. Required claims are present and `sub` is a lowercase hyphenated GUID.
7. `cluster` equals the host entry's cluster, or both are absent. The subject is scoped by the entry alone (6.4), so a disagreeing host is misconfigured.
8. Mint the issued JWT (6.4).

**Success (HTTP 200)**

```json
{
  "access_token": "<issued JWT>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "N_A",
  "expires_in": 300
}
```

`token_type` is `N_A` because the issued token is a JWT assertion rather than an access token. Clients that expect `Bearer` should ignore the field and use `access_token`.

**Errors (HTTP 400)** carry a JSON `error` and a generic `error_description`: `invalid_request` for missing or malformed fields and for any problem with the host token, `invalid_target` if an audience allowlist is configured and the audience is not on it (or a `resource` parameter is sent), and `unsupported_grant_type` for any other `grant_type`. RFC 8693 section 2.2.2 requires `invalid_request`, not `invalid_grant`, when the `subject_token` is invalid or unacceptable by policy (verified). Detail goes to logs, never to the caller. Rate-limit by source address.

### 6.4 Issued JWT

Header: `{"alg":"ES256","typ":"JWT","kid":"<issuer key thumbprint>"}`

| Claim | Value |
| --- | --- |
| `iss` | The issuer URL, exactly as in the discovery document (https, no trailing slash) |
| `sub` | `cluster:<cluster>/<vmid>` if the signing key's allowlist entry has a cluster, otherwise `host:<host>/<vmid>`. The VM ID is the host token's `sub` |
| `aud` | The requested audience, as a single string |
| `iat`, `nbf`, `exp` | Now; `exp` = `iat` + 5 minutes by default, 10 minutes at most (proposed) |
| `jti` | Random 128-bit value |
| `vm_name`, `host`, `cluster` | Informational: `vm_name` is host-asserted, `host` and `cluster` come from the allowlist. Consumers authorize on `iss` and `sub` only |

Any VM can request any audience unless an audience allowlist is configured. The audience says who a token is meant for. It does not say the VM may use that service.

### 6.5 Discovery document and JWKS

`GET /.well-known/openid-configuration` returns JSON with these members:

- `issuer`: the issuer URL
- `jwks_uri`: where the keys are served
- `token_endpoint`: the `/token` URL
- `response_types_supported`: `["id_token"]`
- `subject_types_supported`: `["public"]`
- `id_token_signing_alg_values_supported`: `["ES256"]`

Vendor documentation that mirrors the OIDC Discovery spec also lists `authorization_endpoint` as required. This service has no authorization endpoint. Federation targets mostly need only the issuer, discovery document and keys, so test each target, then either omit the field or point it at a URL that returns an error.

`GET <jwks_uri>` returns the signing keys:

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "<base64url>",
      "y": "<base64url>",
      "kid": "<thumbprint>",
      "use": "sig",
      "alg": "ES256"
    }
  ]
}
```

Every key carries `kid`, `use` set to `sig`, and `alg`. Federation guides call out `use: sig` and a `kid`. During rotation publish the current and the previous key (section 7).

**Hosting.** Entra fetches the discovery document and JWKS over public HTTPS. For Entra, serve those two documents as static files on public hosting while `/token` stays internal. GCP can take uploaded JWKs instead of fetching them (`--jwk-json-path`), so it needs no public hosting.

### 6.6 What a consumer must check

A consumer that accepts an issued JWT should do the following, using any standard OIDC or JWT library. This is the same validation it would apply to any OIDC token:

1. Verify the signature against the issuer's JWKS, accepting only ES256 (or RS256 if the issuer is configured for it).
2. Require `iss` to equal the issuer URL and `aud` to equal the consumer's own audience.
3. Require `nbf` and `exp` to hold, allowing 2 minutes of clock skew.
4. Take the identity from `iss` and `sub` only, and treat `sub` as an opaque string. `vm_name`, `host` and `cluster` are informational.
5. Decide for itself what that identity may do. Proof only says who the VM is.

## 7. Trust and key management

Trust starts with one file: the allowlist of host public keys on the issuer. Everything else follows from it.

### 7.1 Host keys

- One ES256 (P-256) key per Hyper-V host, generated on that host. Only the public key leaves the host.
- A non-exportable CNG machine key in the Microsoft Software Key Storage Provider, which every Windows host has. No TPM is used. CNG refuses to export the private key, and the key file is protected by its ACL: SYSTEM and Administrators, plus read (which is what signing needs) for the refresher's service account. Any local administrator can use the key, so host administrators are inside the trust boundary.
- `kid` is the RFC 7638 JWK thumbprint of the public key. The issuer recomputes it when it loads the allowlist, which catches pasted-key mistakes.
- A replaced host gets a new key and an allowlist edit. Do not plan to migrate host keys.

### 7.2 Allowlist

Stored in your existing GitOps repository, changed by reviewed pull request, delivered to the pods as a ConfigMap, and read by the issuer from a mounted file.

```yaml
version: 1
hosts:
  - host: hv-host-01
    cluster: prod
    keys:
      - kid: <thumbprint>
        status: active          # active | retired
        not_after: 2027-06-30   # optional
        jwk: { kty: EC, crv: P-256, x: <base64url>, y: <base64url> }
```

- An unknown `kid` is rejected. A `retired` key is accepted until `not_after` and then ignored. `not_after` is a `YYYY-MM-DD` date and covers that whole UTC day; it also ends an `active` key. A `retired` key must have one: to stop trusting a key now, remove it.
- Reload on file change with an atomic swap. A file that fails validation is refused: keep the previous list and alert. Mount the ConfigMap as a directory, not as a subPath mount, because Kubernetes does not update subPath mounts (verify on your cluster version).
- Removing a key stops new exchanges immediately. Tokens already issued live until they expire, at most 10 minutes. This is allowlist hygiene, not a revocation feature.
- A host's `cluster` scopes the subjects of the VMs it signs for (6.4), so give every host in a failover cluster the same `cluster`, and give a standalone host none. KVP follows a VM through live migration, so list every host in a cluster that may sign for its VMs. A VM gets a new subject if it moves to another cluster or standalone host, or if its host's `cluster` changes here.
- Host and cluster names are 1 to 253 letters, digits, `.`, `-` or `_`, starting with a letter or digit, so subjects parse unambiguously. Other names fail validation.

### 7.3 Rotation

- Host key: add the new key to the allowlist, switch the refresher to it, and remove the old key after one token lifetime.
- Issuer signing key: publish the new public key in the JWKS first. Wait for caches (at least the maximum token lifetime plus the JWKS cache time), then start signing with it. Remove the old key after the same wait following its last use. Give the JWKS a short `Cache-Control`, for example 5 minutes.

### 7.4 Issuer signing key

- ES256, delivered as a Kubernetes Secret through your GitOps secret handling and mounted read-only into the pod. Moving it into a KMS or HSM later is possible behind .NET's `ECDsa` abstraction.
- Every replica mounts the same Secret, so all replicas sign with one key and a token from any replica verifies the same way. Rotation is staged through the JWKS (7.3) and delivered through GitOps.
- This key is the most sensitive secret in the system, because every verifier and federation target trusts it. Back it up and test the restore.

### 7.5 Time

Every issuer, host and verifier needs NTP. Validation allows 2 minutes of clock skew. The issuer checks host tokens against its own clock, and consumers check issued tokens against theirs.

## 8. Operations

A stateless issuer and a small refresher on each host keep operations simple. The real work is watching token freshness.

**Deployment**

- Issuer: a stateless ASP.NET Core service in a Kubernetes Deployment with two replicas spread across nodes, a Service, and TLS at your existing ingress. Readiness and liveness probes; a pod reports ready only after the allowlist has loaded. Configuration (issuer URL, token lifetimes, optional audience allowlist) and the allowlist arrive as ConfigMaps through your GitOps repository, and the signing key arrives as a Secret.
- Refresher: a Windows service on each Hyper-V host (`proof-refresher`), running as its virtual account `NT SERVICE\proof-refresher`. The account needs membership of Hyper-V Administrators, to see VMs and call the WMI KVP methods, and read access to the host key. The MSI grants both with `proof-refresher service grant`. Tested on Windows Server 2025: with the membership, the account's KVP writes succeed; without it, Hyper-V shows the account no VMs, so nothing is written and nothing fails visibly.
- A TLS certificate for the issuer name at your ingress. VM images must trust its CA.

**Logging.** Structured logs for every exchange: time, outcome, host token `jti`, `sub`, host `kid`, audience and source address. Never log tokens, keys or full claim sets.

**Monitoring and alerts**

- Refresher: last successful KVP write per VM. Alert if any running VM's token is older than its lifetime.
- Issuer: exchange count by outcome, allowlist reload failures, and time until the oldest JWKS key may be removed.
- Host clock offset against the issuer.

**Failure modes**

| Failure | Effect | Response |
| --- | --- | --- |
| Refresher down on a host | Tokens expire within 20 minutes; token requests from that host's VMs fail. Issued tokens stay valid until they expire | Alert on stale tokens |
| Issuer down | Exchanges fail; consumers keep accepting unexpired tokens | Two replicas |
| Allowlist file invalid | Issuer keeps the previous list | Alert; fix through a pull request |
| Clock skew beyond 2 minutes | Exchanges fail with `invalid_request` | Fix NTP |
| Host key lost or replaced | VMs on that host get no tokens until the new key is allowlisted | Allowlist the new key as part of the host rebuild |
| Issuer key lost | Nothing can be issued; verifiers see an unknown `kid` | Restore from backup |

**Backups.** The allowlist and issuer configuration live in the GitOps repository. Back up the signing key separately: a lost Secret means a new key and a JWKS rotation.

## 9. Image requirements

Each image carries the VM client and what it needs to read KVP. It carries no secrets and no tokens.

### Linux

- `hv_kvp_daemon` installed and enabled. The package name varies by distribution; check yours.
- `proof` at `/usr/bin/proof` (the .deb installs it there), and `/etc/proof/config.json` holding the issuer URL and CA bundle path. The issuer URL is baked in, not learned from KVP.

### Windows

- The Data Exchange integration service enabled on the VM (a Hyper-V setting).
- `proof.exe` and its configuration under ProgramData, with the issuer's CA in the trust store.

### Both

- No token, key or credential is baked in.
- Any program that calls the client must tolerate a missing token (the refresher may not have run yet) and retry.

## 10. Gotchas

Fourteen traps to design around. "Verified" means I confirmed it in documentation during our discussion. "Verify" means check it in phase 0 before relying on it.

| # | Gotcha | What to do | Status |
| --- | --- | --- | --- |
| 1 | A KVP value holds at most 2048 bytes including the terminator, a key at most 512, and the host side expects UTF-16 | 1023 characters per value; drop `vm_name` if a token would exceed it | Verified (kernel header, and measured on the host) |
| 2 | Linux guests need `hv_kvp_daemon` running | Install and enable it in the image | Verified |
| 3 | KVP entries persist until deleted and move with the VM during live migration | Overwrite on arrival and on every refresh; allowlist every host in a cluster | Verified (documentation, and a cluster live migration on Windows Server 2025) |
| 4 | `AddKvpItems` refuses an existing key (32773) and `ModifyKvpItems` refuses a missing one (32779) | Upsert as Modify, then Add on 32779 | Verified (Windows Server 2025) |
| 5 | `VirtualMachineName` in the guest parameters changes immediately when a VM is renamed | Treat the name as mutable; identity is the VM ID | Verified |
| 6 | An import that registers in place or restores keeps the VM ID, so two live VMs on different clusters or standalone hosts can share one. A failover cluster refuses a second VM with an ID it already has | Subjects are scoped by cluster or host (6.4). Still generate a new ID on copy | Verified (Import-VM documentation; refusal within a cluster seen restoring backups while the source existed) |
| 7 | Any process that can read the External pool can read the token. On Windows the `External` key grants read to Authenticated Users (verified on a Windows Server 2025 guest). On Linux, upstream `hv_kvp_daemon` creates pool files mode 0644 in a 0755 `/var/lib/hyperv`, readable by every account unless its service runs with a narrower umask (from the daemon source; check `ls -l` on a real guest of each distribution) | Treat the host token as readable by any account in the VM; rely on short lifetimes | Partly verified |
| 8 | Entra and AWS may not accept ES256 from an external issuer | Test each target; fall back to RS256 for issued tokens | Verify (GCP accepts RS256 or ES256: verified) |
| 9 | Entra must reach the discovery document and JWKS over public HTTPS, and federation guides want `kid` and `use: sig` on keys | Host the two documents as static files; always set both fields | Verified (vendor guides) |
| 10 | Any VM can request any audience | Consumers check `iss` and `sub`, never the audience alone | Design note |
| 11 | An RFC 8693 response for a JWT carries `token_type` of `N_A` | Clients read `access_token` and ignore `token_type` | Verified (vendor examples) |
| 12 | Host keys cannot be exported | Plan a new key and an allowlist edit when a host is rebuilt | Verified (CNG export policy, tested) |
| 13 | EdDSA is not built into Microsoft.IdentityModel | Use ES256 | Verify |
| 14 | JOSE libraries have had security advisories (jwx fixed a verification bypass in 1.2.11 and a padding-oracle issue in 2.0.11) | Pin versions, update promptly, watch advisories | Verified (jwx changelog) |

## 11. Security hygiene from day one

A checklist to hold the build to. Each item is cheap now and expensive later.

**Token validation**

- [ ] Pin the algorithm: `ValidAlgorithms` contains only `ES256`, and the token header never chooses the verification method.
- [ ] Reject `none`, HS256/384/512 and any encrypted token.
- [ ] Require `typ`, `iss`, `aud`, `sub`, `iat`, `nbf`, `exp` and `jti`, and check each one.
- [ ] Use different `typ` values and audiences for host tokens and issued tokens, so one can never be accepted as the other.
- [ ] Cap lifetimes ourselves (`exp` minus `iat`). Lifetime validation checks that a token has not expired, not that its lifetime is short.
- [ ] Allow 2 minutes of clock skew and no more.
- [ ] Use `kid` only to pick among keys already on the allowlist or JWKS. Never fetch a key from a URL named in a token.
- [ ] Limit token size before parsing.
- [ ] Return generic errors to callers and log the detail.

**Keys**

- [ ] Host keys are non-exportable and generated on the host.
- [ ] Host tokens and issued tokens use separate keys.
- [ ] The issuer signing key is a Secret mounted read-only, with RBAC limiting who can read it, backed up, and its restore tested.
- [ ] `kid` is the JWK thumbprint, recomputed and checked on load.
- [ ] Rotate on a schedule, and practise a rotation before you need one.

**Service**

- [ ] TLS only, with a current minimum version. No tokens in URLs or query strings.
- [ ] Rate limits and request size limits on `/token`.
- [ ] Logs never contain tokens or keys.
- [ ] The issuer pod runs as non-root with a read-only root filesystem, and the refresher runs under a dedicated, least-privileged Windows account.
- [ ] The allowlist changes only by reviewed pull request, with an audit trail.

**Supply chain**

- [ ] Pin NuGet versions with lock files, and turn on automated dependency updates.
- [ ] Subscribe to security advisories for Microsoft.IdentityModel and .NET.
- [ ] Produce an SBOM for each release and sign the Windows binaries.

**Data**

- [ ] No personal data in claims. `vm_name`, `host` and `cluster` are the only extras, and they are marked informational.
- [ ] Scope `sub` by the allowlist entry, never by the host token's claims.

## 12. Test plan

Negative tests matter more than positive ones here: a validator that accepts a bad token is the failure that counts.

**Negative tests (issuer and token validation).** Each must be refused with a generic error.

- An expired token; a not-yet-valid token; clock skew just inside and just outside 2 minutes.
- Wrong audience, wrong `typ`, wrong issuer, a missing required claim, a lifetime above the cap.
- `alg: none`; `alg: HS256` signed with the public key as the secret; `alg: RS256`.
- An unknown `kid`; a known `kid` with a signature from a different key; a tampered payload.
- A token over the size limit.
- An issued JWT presented as a host token, and a host token presented to a consumer.
- A key removed from the allowlist; an allowlist file that fails validation.

**End-to-end tests**

- Host token to issued JWT to verification with a standard JOSE library, for Linux and Windows VMs.
- Live migration: a VM keeps getting valid tokens before and after it moves.
- Refresher outage: tokens expire on schedule and recovery is automatic.
- A rotation drill for host keys and the issuer key, including the JWKS overlap.

**KVP tests (phase 0)**

- Values near the limit: 1023 characters accepted, 1024 refused (done on the host; still check what the Linux and Windows guests read back).
- Update behavior: add, modify, and add on an existing key (done on the host).
- Pool file parsing on Linux, registry reads on Windows, and who can read them.
- Duplicate VM ID behavior after copy and import: the same ID on two clusters, or a cluster and a standalone host, gives two subjects.

**Interoperability**

- A federation test against GCP (RS256 or ES256 accepted), then Entra and AWS with ES256, falling back to RS256 if rejected.
- Verify a token with a JOSE library in another language against the JWKS, to confirm nothing depends on quirks of our own library.

**Robustness.** Fuzz our wrappers around token parsing and the allowlist loader. The JOSE library itself is not ours to test.

## 13. Phases

Build in three phases. Phase 1 delivers the core, and Phase 2 adds federation.

&#91;embedded content: roadmap · 3 phases, 3 gates\]

Every gate also requires the negative test suite in section 12 to pass. Phase 0 settles the open items marked as phase 0 tests in section 14 before any production code depends on them.

## 14. Open items

Twelve items remain open. Some need your decision; the rest are checks to run before or during the build.

| # | Open item | Settled by |
| --- | --- | --- |
| 1 | Confirm C#/.NET for the issuer and VM client (decision 9) | You |
| 2 | Issuer replicas: with a Kubernetes Deployment, all replicas mount one shared signing Secret, which is the simple path. Confirm it, and decide how key rotation is staged through GitOps | You, before phase 1 |
| 3 | Whether Entra and AWS accept ES256 from an external issuer; RS256 is the fallback for issued tokens | Phase 2 test |
| 4 | KVP behavior: host side settled (Add versus Modify, 1023-character values; see 6.2). Read permissions are verified on Windows and taken from the daemon source on Linux (gotcha 7). Still open: what each guest reads back for a real token, and the pool file mode on a real Linux guest | Phase 0 test |
| 5 | Settled: duplicate VM IDs across clusters or standalone hosts get distinct subjects (decision 2); a failover cluster refuses duplicates within it | Done |
| 6 | Settled: the refresher's virtual account needs Hyper-V Administrators membership, and that is enough (tested on Windows Server 2025). Without it the account sees no VMs | Done |
| 7 | Settled: host keys use the CNG software key storage provider, no TPM (decision 13). `CngKey` creates a non-exportable P-256 machine key there (tested) | Done |
| 8 | .NET specifics: `JsonWebTokenHandler` settings for `ValidAlgorithms` and lifetime caps, and self-contained single-file size (the refresher is 73.5 MB). NativeAOT is out for the refresher, because `System.Management` needs built-in COM | Phase 0 test |
| 9 | The `hv_kvp_daemon` package name for each distribution in your images | Image build |
| 10 | Audience policy: free-form, or an allowlist of audiences | You, before phase 1 |
| 11 | Token lifetimes: host token 20 minutes refreshed every 5, issued token 5 minutes (10 at most) | You |
| 12 | The issuer's DNS name, its TLS certificate source at the ingress, and public hosting for the discovery document and JWKS | You, TLS before phase 1, hosting before phase 2 |

## 15. References

Pages consulted for this specification. Items marked Verified in section 10 come from these.

**Hyper-V and Windows**

- [Hyper-V Data Exchange (KVP pools, registry paths, live migration)](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/integration-services-data-exchange)
- [KVP size limits in `hyperv.h`](https://git.zx2c4.com/linux-dev/plain/include/linux/hyperv.h?id=99ffe6f4c2984959cd327bb4143eea9fec0052ef)
- [`Msvm_VirtualSystemManagementService` (AddKvpItems, ModifyKvpItems, RemoveKvpItems)](https://learn.microsoft.com/en-us/windows/win32/hyperv_v2/msvm-virtualsystemmanagementservice)
- [Guest parameters update live on VM rename](https://weblogs.asp.net/owscott/hyper-v-getting-host-information-from-the-guest-vm)
- [Guest parameter keys including `VirtualMachineId` (hyperkv)](https://pypi.org/project/hyperkv/)
- [CNG key storage providers (Microsoft Platform Crypto Provider)](https://learn.microsoft.com/en-in/windows/win32/seccertenroll/cng-key-storage-providers)

**.NET and JOSE libraries**

- [`TokenValidationParameters` (Microsoft.IdentityModel)](https://learn.microsoft.com/dotnet/api/microsoft.identitymodel.tokens.tokenvalidationparameters)
- [Signing JWTs with ECDSA in .NET](https://www.scottbrady.io/c-sharp/jwt-signing-using-ecdsa-in-dotnet-core)
- [lestrrat-go/jwx (see its Changes file for the security fixes)](https://github.com/lestrrat-go/jwx)

**Token exchange, OIDC and federation**

- [RFC 8693 token exchange parameters](https://www.authlete.com/developers/token_exchange)
- [RFC 8693 response example showing `token_type` of `N_A`](https://shopify.dev/docs/agents/profiles/buyer-linked-tokens.md)
- [OIDC provider metadata fields](https://developer.broadcom.com/xapis/vmware-identity-broker/latest/acs/t/tenant/.well-known/openid-configuration/get)
- [GCP workload identity federation with other providers](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-providers)
- [Entra federation with SPIFFE/SPIRE (`use: sig` on JWKS keys)](https://docs.azure.cn/en-us/entra/workload-id/workload-identity-federation-spiffe-spire)
- [Entra must reach the discovery document and JWKS over HTTPS](https://docs.crewai.com/en/enterprise/features/secrets-manager/azure-workload-identity)
- [Prior art: tsiam, a node-identity JWT service for federation](https://github.com/italypaleale/tsiam)
