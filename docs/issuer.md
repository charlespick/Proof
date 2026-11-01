# Deploying the issuer

The issuer is the one central piece of Proof. It checks the token a Hyper-V host gave a VM, and if the host is one you trust, returns a short-lived JWT for the service the VM wants to talk to. It also publishes the OIDC discovery document and signing keys that those services use to verify the JWT.

It is a small, stateless service shipped as a container image. Kubernetes is the ideal home for it, but any place that runs containers behind HTTPS works.

```
ghcr.io/charlespick/proof-issuer:<version>
```

## Before you start

You need to decide three things:

- **The issuer URL**, for example `https://id.example.com`. It must be HTTPS with no trailing slash. It becomes the `iss` of every JWT, and VMs and consumers must be able to reach it. Choose carefully, because changing it later means re-issuing trust everywhere.
- **A signing key**, an ECDSA P-256 private key in PEM form. Every JWT the issuer mints is signed with it, so treat it like any other root credential.
- **A host allowlist**, a YAML file listing the Hyper-V hosts whose VMs may get tokens. It can start empty.

Create the signing key:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out signing-key.pem
```

## The host allowlist

The allowlist is the issuer's list of trusted Hyper-V hosts, identified by public key. Keep it in version control and change it by pull request, because every line is a decision to trust a machine.

```yaml
version: 1
hosts:
  - host: hv-host-01
    cluster: prod            # omit for a standalone host
    keys:
      - kid: <thumbprint>
        status: active       # active or retired
        not_after: 2027-06-30   # optional
        jwk: { kty: EC, crv: P-256, x: <base64url>, y: <base64url> }
```

You don't write these entries by hand. The [refresher](refresher.md) prints a ready-made entry for its host with `proof-refresher key show`.

- Give every host in a Hyper-V failover cluster the same `cluster` name, and give standalone hosts none. A VM's identity includes its cluster, so a VM keeps its identity when it live-migrates within the cluster.
- A key marked `retired` still works until its `not_after` date, which is how you rotate keys gracefully. To stop trusting a key immediately, delete it.
- The issuer rereads the file every 10 seconds. If an edit makes the file invalid, the issuer keeps using the last good version and logs why.

## Configuration

The issuer reads settings from environment variables prefixed `Proof__`.

| Setting | Default | Meaning |
| ------- | ------- | ------- |
| `Proof__IssuerUrl` | required | The issuer URL described above |
| `Proof__AllowlistPath` | `/etc/proof/allowlist/allowlist.yaml` in the image | The host allowlist |
| `Proof__SigningKeyPath` | `/etc/proof/signing/signing-key.pem` in the image | The signing key |
| `Proof__AdditionalPublicKeyPaths__0` | none | Extra public keys to publish, used when rotating the signing key |
| `Proof__IssuedTokenLifetime` | `00:05:00` | How long issued JWTs live, up to `00:10:00` |
| `Proof__AllowedAudiences__0` | none (any) | Restrict which audiences VMs may request. Strongly recommended once you know your consumers |
| `Proof__TokenRequestsPerMinute` | `60` | Rate limit per client address |
| `Proof__TrustedProxies__0` | none | Addresses or CIDR networks of your reverse proxy. See below |
| `Proof__AllowlistPollInterval` | `00:00:10` | How often the allowlist is reread |

The image runs as a non-root user (UID 1654), serves plain HTTP on port 8080 and logs JSON to stdout. Terminate TLS in front of it. Make sure the mounted files are readable by that user.

### Behind a proxy

When the issuer sits behind an ingress or load balancer, every request appears to come from the proxy, so rate limiting would treat all VMs as one caller. Set `Proof__TrustedProxies__0` to the proxy's address or network (for example `10.0.0.0/16`). The issuer then reads the client address from the `X-Forwarded-For` header, and only on connections from those proxies. Don't set `ASPNETCORE_FORWARDEDHEADERS_ENABLED`; the issuer refuses to start with it, because it would trust that header from anyone.

## Running it

### With Docker

```sh
docker run -d --name proof-issuer -p 8080:8080 \
  -e Proof__IssuerUrl=https://id.example.com \
  -v "$PWD/allowlist:/etc/proof/allowlist:ro" \
  -v "$PWD/signing:/etc/proof/signing:ro" \
  ghcr.io/charlespick/proof-issuer:<version>
```

Here `allowlist/` holds `allowlist.yaml` and `signing/` holds `signing-key.pem`. Put a reverse proxy in front for TLS, or have the issuer serve TLS itself by adding `-e ASPNETCORE_HTTPS_PORTS=8443`, a certificate and key mounted at some path, and `ASPNETCORE_Kestrel__Certificates__Default__Path` and `...__KeyPath` pointing at them.

### On Kubernetes

Run at least two replicas. They are stateless and all mount the same signing key, so a token minted by one verifies the same as any other.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: proof-allowlist
data:
  allowlist.yaml: |
    version: 1
    hosts: []
---
apiVersion: v1
kind: Secret
metadata:
  name: proof-signing-key
stringData:
  signing-key.pem: |
    -----BEGIN EC PRIVATE KEY-----
    ...
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: proof-issuer
spec:
  replicas: 2
  selector:
    matchLabels: { app: proof-issuer }
  template:
    metadata:
      labels: { app: proof-issuer }
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1654
        fsGroup: 1654
      containers:
        - name: issuer
          image: ghcr.io/charlespick/proof-issuer:<version>
          env:
            - { name: Proof__IssuerUrl, value: "https://id.example.com" }
            - { name: Proof__TrustedProxies__0, value: "10.0.0.0/16" }
          ports:
            - containerPort: 8080
          livenessProbe:
            httpGet: { path: /healthz/live, port: 8080 }
          readinessProbe:
            httpGet: { path: /healthz/ready, port: 8080 }
          volumeMounts:
            - { name: allowlist, mountPath: /etc/proof/allowlist, readOnly: true }
            - { name: signing, mountPath: /etc/proof/signing, readOnly: true }
      volumes:
        - name: allowlist
          configMap: { name: proof-allowlist }
        - name: signing
          secret: { secretName: proof-signing-key }
---
apiVersion: v1
kind: Service
metadata:
  name: proof-issuer
spec:
  selector: { app: proof-issuer }
  ports:
    - { port: 80, targetPort: 8080 }
```

A few notes:

- Replace the `Secret` with whatever you use to manage secrets. Never commit a real signing key.
- Mount the allowlist `ConfigMap` as a directory, as above, not with `subPath`. Kubernetes doesn't update `subPath` mounts, so edits would never reach the issuer.
- Expose the Service through your ingress with a TLS certificate for the issuer URL. VM images must trust the CA that signed it.
- The signing key is read at startup, so roll the pods after changing it.

## Checking that it works

Once the issuer is running behind its URL:

```sh
curl https://id.example.com/.well-known/openid-configuration
curl https://id.example.com/.well-known/jwks.json
```

The first returns the discovery document and the second returns your public signing key. The issuer reports ready at `/healthz/ready` once an allowlist has loaded, and alive at `/healthz/live`.

To try the issuer without a container, run it from the source tree:

```sh
Proof__IssuerUrl=https://id.example.com Proof__AllowlistPath=allowlist.yaml \
  Proof__SigningKeyPath=signing-key.pem dotnet run --project src/Proof.Issuer
```

## What consumers need to know

Services that accept Proof tokens need no Proof-specific code. Anything that supports OIDC or JWT validation works. Point it at the issuer URL, require the audience your service expects, and use the `sub` claim as the VM's identity.

`sub` has the form `cluster:<cluster>/<vm-id>`, or `host:<host>/<vm-id>` for a VM on a standalone host. Treat it as an opaque string. Other claims (`vm_name`, `host`, `cluster`) are informational. Don't make authorization decisions from them.

The endpoints are:

| Endpoint | Purpose |
| -------- | ------- |
| `POST /token` | Token exchange ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)). Used by the client. Keep this internal if you can. |
| `GET /.well-known/openid-configuration` | OIDC discovery |
| `GET /.well-known/jwks.json` | Public signing keys |
| `GET /healthz/live`, `GET /healthz/ready` | Health checks |

Some cloud providers fetch the discovery document and keys over the public internet, even when VMs reach `/token` privately. If that's your case, publish the two `/.well-known` documents on a public address and set `TokenEndpoint` in the [client](client.md) so VMs still use your internal `/token`.

## Rotating the signing key

1. Generate a new key and add its public half to `Proof__AdditionalPublicKeyPaths__0`, then roll the pods. Verifiers now see both keys.
2. Wait longer than the token lifetime plus any caching in your verifiers.
3. Switch `Proof__SigningKeyPath` to the new key and roll again.
4. After another wait, remove the old public key.

## Operating notes

- **Clocks matter.** Keep the issuer, hosts and consumers on NTP. Tokens are checked with two minutes of tolerance.
- **Monitoring.** The issuer emits metrics on the `Proof.Issuer` meter: exchanges by outcome and allowlist reload failures.
- **Revocation.** Removing a key from the allowlist stops new tokens immediately. Tokens already issued stay valid until they expire, at most ten minutes.
- **Back up the signing key.** Losing it means issuing a new one and rotating every consumer's trust.

Next: [install the refresher](refresher.md) on your Hyper-V hosts.
