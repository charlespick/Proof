# Security

This page explains what Proof trusts, what it doesn't, and where the edges are. It is worth reading before you rely on Proof for anything that matters.

The short version: Proof proves *which VM* is calling, using the Hyper-V host as the source of truth. It is strong against a VM pretending to be another VM, and it is deliberately not a defence against code running inside the VM itself.

## Trust zones

Proof has four zones, and each one trusts the one before it.

| Zone | Who is in it | What it is trusted for |
| ---- | ------------ | ---------------------- |
| **Hyper-V host** | The host OS and its administrators, and anyone who can write its VMs' notes | Saying which VM is which, and what its notes say it is for. Anyone who can administer the host can use its signing key, read and change VM notes and impersonate any VM on it |
| **Issuer** | The issuer service and whoever controls its signing key and allowlist | Deciding which hosts to believe, and vouching for them to everyone else |
| **VM** | Every program running in the guest | Nothing beyond its own identity. See below |
| **Consumers** | Services that accept Proof's JWTs | Deciding what an identified VM may do |

The chain of trust is short:

1. You put a host's public key on the issuer's **allowlist**. That list is the only root of trust. If a key isn't on it, nothing from that host is accepted.
2. The host signs a token naming a VM with a private key that never leaves the host. The key is non-exportable and held by the Windows key storage provider.
3. The issuer verifies that token against the allowlist and signs a JWT with its own key.
4. Consumers verify the JWT against the issuer's published public keys.

This means:

- **Compromising a VM** gets an attacker that VM's identity, and nothing else. They cannot obtain tokens for other VMs.
- **Compromising a host** (or its administrator) gets an attacker the identity of every VM on that host, and of VMs they claim to be running, with any tenant and tags they like. Treat hosts that run Proof like the domain controllers of this system. If a host is lost, remove its key from the allowlist.
- **Compromising the issuer's signing key** lets an attacker mint a JWT for any identity. Store it carefully, back it up, and limit who can read it.
- **Compromising the allowlist** lets an attacker add their own host. Change it only through reviewed changes.

## VM identity and who sets it

Each JWT carries a tenant, an assigned ID and security tags, taken from the [`identity:` block](refresher.md#vm-identity) in the VM's Hyper-V notes. Consumers can authorize on them, which makes **VM notes an authorization input.** Whoever can write a VM's notes decides what tenant, assigned ID and tags its tokens carry. That includes:

- Hyper-V host administrators, and members of Hyper-V Administrators.
- Anyone you have delegated VM administration to, through Hyper-V's own permissions or a management tool such as System Center.
- Any service that holds Hyper-V Administrators. Proof's own `proof-metadata-host` service is one: it edits notes to clear secrets, so a compromise of it, the code that talks to guests, could also rewrite any VM's identity on that host.
- Restore, import and replication tools, which bring back a VM's notes with it.

Adding an identity widens what each of those accounts can do, from administering VMs to deciding what the VMs are allowed to reach. Review who holds them with that in mind.

Everything attached to one issuer is **one trust environment**: every host on its allowlist is run by one operator, and any of them may vouch for any tenant or tags. The allowlist doesn't limit which tenants or tags a host may assert, and the subject doesn't name the host that signed. Proof can't separate tenants from each other, because the only way to set a VM's identity is through the Hyper-V API. A deployment where tenants mustn't be able to set each other's identity needs a layer in front of that API that controls who may write which VMs' notes, or a separate issuer and hosts for each.

Proof is still only an identity provider. A tenant or a tag is an assertion about a VM, not a permission. Your services decide what a VM with that identity may do, and should grant no more than it needs.

**Changing or removing an identity isn't instant revocation.** The refresher replaces or removes the VM's token within about a second, so the normal path, `proof token` inside the VM, stops getting the old identity straight away. But a host token already copied out of the VM stays valid for up to 20 minutes, and a JWT already issued for up to 10 (5 by default). If a VM may have been compromised, assume it holds its old identity until those times have passed.

## What a process inside a VM can do

Anything running in a VM, at any privilege level, can obtain that VM's tokens.

The host writes its token into the VM's Hyper-V Data Exchange store, and the guest tooling makes that store readable to ordinary accounts: on Windows the registry key grants read to Authenticated Users, and on Linux the pool file is typically world-readable. So any local user or process can read the host token and run `proof token` to exchange it for a JWT.

That is deliberate, and it is the same model as cloud providers use. A VM's identity is the VM's, not that of any one program in it. If you need to keep one program's credentials from another on the same VM, give them separate VMs, or put your own controls between them.

Proof limits the damage with short lives rather than by hiding the token:

- The host token lasts 20 minutes and is refreshed about every five. It is only useful for getting JWTs from the issuer, and it is only accepted by that issuer.
- Issued JWTs last five minutes by default, and ten at most.
- Stealing a token buys minutes of access, not a standing credential.

Tokens are not revoked once issued. Removing a host's key stops new exchanges at once, but a JWT already minted stays valid until it expires.

## Comparison with EC2

If you know the EC2 instance metadata service (IMDS), you already know most of Proof's model.

| | EC2 | Proof |
| - | --- | ----- |
| Where the metadata lives | `169.254.169.254` on a link-local network | `127.0.0.1:8169`, served by a local service that talks to the host over a Hyper-V socket |
| Needs a network? | Yes, a virtual one | No. Provisioning works on a VM with no network adapter |
| How the platform knows which VM is asking | The hypervisor's network knows which instance owns the connection | The hypervisor reports the calling VM's ID on every socket connection |
| Who can read it inside the instance | Any process, unless blocked locally | Any process |
| Format | EC2's own | OpenStack's, which cloud-init and Cloudbase-Init both read with static network configuration |
| Request protection | IMDSv2 requires a session token and refuses forwarded requests | Refuses requests that look forwarded or browser-originated. OpenStack's clients send no session token, so none is asked for |
| Credentials | Temporary IAM role credentials | A JWT you exchange for the audience you need |
| Secrets in user data | Remain readable for the life of the instance | Marked `!sensitive`, then erased from the VM's notes once provisioning finishes |

The most important line is the same on both: **any program in the VM can ask for the VM's data and credentials.** If an attacker can run code in your VM, they can read its metadata and get its tokens. On EC2 this is why you scope instance roles narrowly. With Proof, it is why consumers should grant each VM only the access it needs.

Two things are different on purpose. First, there is no network path, so there is no "stolen from another host on the same network" scenario, and no address for something to spoof. Second, the sensitive-value mechanism lets you hand a VM a bootstrap secret and have it removed from the host's records once the VM has used it, which user data on EC2 cannot do.

## How the metadata socket knows who is calling

The VM's `proof-metadata` service doesn't hold any data. It forwards each request to the refresher on the host over a Hyper-V socket (`AF_HYPERV` on Windows, `AF_VSOCK` on Linux).

A request has no field for "who am I". Instead, the hypervisor itself reports the ID of the VM that opened each connection. The host uses only that ID to find the VM's notes, and it never reads an identity from the contents of a request. A VM can therefore only ever ask for its own data. It can't name another VM or alter the ID it connects with.

The rest of the host-side protections treat the guest as untrusted:

- Requests are tiny (1 KB at most). A guest has 5 seconds to send its request, and a connection lasts 30 seconds at most.
- Each VM is limited to 4 connections at once and 120 a minute, both checked before anything is read from the guest. The host takes 64 connections at once across all VMs. One VM can't use up those connections, but about 16 compromised VMs working together could delay metadata for the others. This only affects availability, and it doesn't affect tokens.
- The service that talks to guests, `proof-metadata-host`, runs apart from the one that signs tokens and has no access to the host key. A bug in the code guests reach doesn't hand over the key directly. The two are not a hard boundary: its account is still in Hyper-V Administrators, which it needs for VMs' notes, so a compromise of it can read and change any VM's settings, including secrets in notes. Treat that group as close to host administrator.
- Nothing a guest sends is ever written to the notes. Reporting that provisioning has finished carries one of two fixed words, and the host writes its own text. OpenStack's password endpoint, where Cloudbase-Init would post the password it set, isn't served.
- A notes block that doesn't parse, uses an unknown tag or key, or uses YAML anchors serves nothing and is logged. A mistyped `!sensitive` can't silently turn a secret into an ordinary value that stays in the notes forever.
- The host verifies its edit before saving. If a secret would remain or the status would be wrong, it writes nothing and the guest can retry.

Inside the VM, the local endpoint is on loopback only. It also refuses requests that look like they came from a web page, with an `Origin` or `X-Forwarded-For` header or a `Host` that isn't a loopback name, which blocks DNS rebinding and cross-site requests from a browser running in the VM.

## Limits to know about

- **Secrets in notes are plain text until cleared.** Anyone who can read the VM's settings (including host administrators and backup tools) can read them until provisioning finishes.
- **Checkpoints keep their own copy of VM settings**, so clearing doesn't reach them. Don't checkpoint a VM holding secrets, or delete those checkpoints.
- **Any process in the VM can report provisioning finished**, which clears the secrets early. A guest that never reports keeps its secrets, so you can clear them from the host with `proof-refresher metadata finish`.
- **Hyper-V Manager's settings dialog saves the notes it opened with.** If it is open when secrets are cleared, saving it can put them back in the notes. They aren't served again, and the next clear removes them.
- **Audiences are not authorization.** Unless you set `AllowedAudiences`, any VM can request a token for any audience. Consumers must check `iss` and `sub`, and decide for themselves whether that VM may do what it is asking.
- **Tokens are bearer credentials.** Keep them out of logs and URLs. Proof's own logs never contain them.
- **Subjects are not guaranteed unique.** Proof keeps no state across VMs, so it doesn't stop two VMs from being given the same tenant and assigned ID; their VM IDs still tell them apart. A VM restored or imported with its ID kept also keeps its notes, so a copy running beside the original has the same subject. Give a copy a new identity, or import it with a new ID, before both run.
- **Names are not identity.** `vm_name` can change at any time. Don't authorize on it.
- **Clocks matter.** Everything is time-limited, and the allowed skew is two minutes. Keep everything on NTP.

## How Proof protects itself

- Only `ES256` is accepted. The `none` algorithm, HMAC algorithms and encrypted tokens are always rejected, and the token header can't choose how it is verified.
- Host tokens and issued JWTs have different types and audiences, so one can never be accepted as the other.
- The issuer only trusts keys on its allowlist. It never fetches a key from a URL in a token.
- Identity values are checked twice: the refresher refuses a block that breaks the rules, and the issuer refuses a host token whose values aren't in their one accepted form, rather than correcting them. Nothing is guessed or filled in from the VM's name.
- Token size is limited before parsing, `/token` is rate limited, and callers get generic errors while details go to the log.
- Settings files on the host and in Windows images must be owned and writable only by administrators, or the program refuses to start.
- Dependencies are pinned with lock files, and the issuer image runs as a non-root user on a minimal base image with no shell.

## Reporting a vulnerability

Please report security problems privately rather than in a public issue. Use the repository's **Security** tab on GitHub to open a private report, and include what you found, how to reproduce it and what it affects.
