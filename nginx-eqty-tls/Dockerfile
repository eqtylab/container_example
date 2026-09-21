# nginx TLS terminator that mints its OWN key inside the PodVM (TEE),
# gets it signed by Let's Encrypt via cert-manager (CSR flow — the key
# never leaves the guest), AND cross-signs the same key with the PodVM
# notary's TEE-bound CA. See entrypoint.sh + ../README.md.
#
# Base is the same nginx:1.27-alpine used by the plain sidecar; it
# already ships curl + wget + /bin/sh. We add only the openssl CLI
# (~2 MB) so the container can generate keys and build CSRs itself.
FROM nginx:1.27-alpine

RUN apk add --no-cache openssl

COPY entrypoint.sh /usr/local/bin/nginx-eqty-tls-entrypoint.sh
RUN chmod +x /usr/local/bin/nginx-eqty-tls-entrypoint.sh

# The stock image's docker-entrypoint runs envsubst templating then
# execs its CMD; we bypass it entirely and drive nginx ourselves.
ENTRYPOINT ["/usr/local/bin/nginx-eqty-tls-entrypoint.sh"]
