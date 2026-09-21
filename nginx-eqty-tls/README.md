# nginx-eqty-tls

NGINX for vNIM pods with automatic TLS key generation, cert-manager
issuance, and EQTY notary signing. The private key is generated locally;
only certificate signing requests (CSRs) are sent to the signers.

## Difference from the base image

The [Dockerfile](Dockerfile) extends `nginx:1.27-alpine`, keeping its
NGINX binary and modules, adding OpenSSL, and replacing the entrypoint
with [entrypoint.sh](entrypoint.sh). OpenSSL installation can also update
shared libraries. The base image has no digest pin, and OpenSSL is unversioned.

| Base NGINX image | This image |
|---|---|
| Uses supplied TLS keys and certificates | Generates an EC P-256 key and requests certificates |
| No certificate lifecycle automation | Uses cert-manager for issuance and renewal, then reloads NGINX |
| No EQTY integration | Requests a notary certificate for the same key and writes a public PEM bundle |
| Runs standard startup hooks and template substitution | Bypasses those hooks and ignores command arguments; starts `nginx -g 'daemon off;'` |

The image does not include the vNIM proxy configuration. Port `40443`,
proxy routes, and the bundle's public URL come from the deployment's
mounted NGINX configuration.

## Runtime behavior

1. Creates `/tls/tls.key` with permissions `0600` if absent; otherwise
   reuses it. Renewal also reuses the key.
2. Submits a cert-manager `CertificateRequest` to the configured issuer
   and writes the returned chain to `/tls/tls.crt`. The key is never
   stored in a Kubernetes Secret.
3. Requests notary signing through `/v1/sign_cert`. Writes
   `/var/www/wellknown/notary-cross-sign.pem`, containing the issuer's
   leaf and chain, notary leaf, notary chain, and notary CA, in that order.
4. Starts NGINX after the certificate passes the startup check. Checks
   hourly for renewal within 30 days of expiry by default. No bootstrap
   self-signed certificate is generated.

Current limitations:

- The startup check only compares issuer and subject; it does not verify
  Let's Encrypt trust or certificate validity.
- Notary failure does not block NGINX startup. The bundle is refreshed
  after certificate issuance or when missing, without an independent
  expiry check.

## Deployment

Use [the example manifest](../manifests/gpt-oss-20b.yaml) for configuration,
volumes, and RBAC. It supplies:

- A `Memory` emptyDir at `/tls`, writable `/var/www/wellknown`, and NGINX
  configuration at `/etc/nginx/conf.d`. Pod replacement loses the key.
- TLS configuration using `/tls/tls.crt` and `/tls/tls.key`, plus the URL
  `/.well-known/eqty/notary-cross-sign.pem`. Its TCP readiness probe checks
  port `40443`, not notary signing.
- A ServiceAccount with `create/get/list/watch/delete` on
  CertificateRequests throughout its namespace, not just its own request.

The cluster also needs cert-manager, an issuer with a working challenge
solver and request approval, and the EQTY notary. Concurrent instances
in one namespace need distinct `CR_NAME` values.

**Host protection depends on the deployment:** a confidential PodVM,
in-guest memory storage, and a Kata agent policy blocking host-driven exec
and other key-access paths. Clients must verify the notary's attestation
binding and match the notary-signed leaf's public key to the TLS connection.
The bundle alone does not prove TEE residency.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `TLS_HOST` | Required | Certificate DNS name |
| `LE_ISSUER` | `letsencrypt` | cert-manager issuer name |
| `LE_ISSUER_KIND` | `ClusterIssuer` | Use `Issuer` for a namespaced issuer |
| `NOTARY_URL` | `http://127.0.0.1:8066` | Notary endpoint |
| `CR_NAME` | `vnim-tls` | Request name; deleted and recreated on issuance |
| `RENEW_DAYS` | `30` | Renewal window before expiry |
| `POLL_INTERVAL` | `10` | Issuance polling interval, seconds |
| `IDLE_INTERVAL` | `3600` | Steady-state check interval, seconds |

`TLS_DIR` defaults to `/tls`; `WELLKNOWN` to `/var/www/wellknown`.
Changing these requires matching mounts and NGINX configuration.

For testing, `START_NGINX=0` runs one reconciliation without NGINX;
`KUBE` and `SA_DIR` override the Kubernetes API URL and ServiceAccount
directory. No automated test suite is included here.

## Build and push

Run from this directory, replacing the registry address:

```bash
REG=registry.example.com:5000
docker buildx build --platform linux/amd64 --provenance=false --sbom=false \
  -t "$REG/vcomp-nim/nginx-eqty-tls:latest" --push .
```

The attestation flags retain the documented workaround for image
unpacking failures in the target environment. Update the deployment's
image reference after pushing; use its digest when pinning a build.
