#!/bin/sh
# nginx-eqty-tls-entrypoint.sh — nginx TLS terminator that owns its key.
#
# Unlike the plain nginx sidecar (which mounts an LE key that
# cert-manager generated on the cluster and stored in a host-readable
# Secret), this container:
#
#   1. generates its OWN EC P-256 key inside the PodVM, on a tmpfs
#      (Memory emptyDir). The private key never touches etcd, never
#      touches cert-manager, and — with `kubectl exec` denied by the
#      kata-agent policy — is unreadable by the host.
#   2. gets that key signed by Let's Encrypt by submitting a raw
#      cert-manager CertificateRequest (CSR flow). cert-manager runs
#      the ACME HTTP-01 order via its traefik solver and returns only
#      the signed public cert — it never sees the key.
#   3. cross-signs the SAME key with the PodVM notary's TEE-bound CA
#      (POST /v1/sign_cert), and publishes the LE+notary bundle at
#      /.well-known/eqty/notary-cross-sign.pem. Because the key is now
#      born in the guest, that bundle is a genuine "this key lives in
#      the TEE" proof, not just an attestation vouching for a
#      cluster-generated key.
#   4. serves nginx with the same vnim-proxy-conf as the DGX sidecar,
#      and keeps the LE cert + notary bundle fresh on a renewal loop
#      (nginx -s reload on any change).
#
# Tooling: /bin/sh (busybox), curl, wget from nginx:alpine + openssl
# added by the Dockerfile. No jq, no kubectl — the Kubernetes API is
# driven with curl + the pod's ServiceAccount token.
set -eu

TLS_HOST="${TLS_HOST:?TLS_HOST (public DNS name) is required}"
TLS_DIR="${TLS_DIR:-/tls}"
WELLKNOWN="${WELLKNOWN:-/var/www/wellknown}"
NOTARY_URL="${NOTARY_URL:-http://127.0.0.1:8066}"
LE_ISSUER="${LE_ISSUER:-letsencrypt}"
LE_ISSUER_KIND="${LE_ISSUER_KIND:-ClusterIssuer}"
CR_NAME="${CR_NAME:-vnim-tls}"
RENEW_DAYS="${RENEW_DAYS:-30}"          # renew LE cert this many days before expiry
POLL_INTERVAL="${POLL_INTERVAL:-10}"    # while an LE order is in flight
IDLE_INTERVAL="${IDLE_INTERVAL:-3600}"  # steady-state re-check cadence
START_NGINX="${START_NGINX:-1}"         # 0 in unit tests

SA_DIR="${SA_DIR:-/var/run/secrets/kubernetes.io/serviceaccount}"  # override in tests
KUBE="${KUBE:-https://kubernetes.default.svc}"

# stderr, so the renewal loop's `$(reconcile)` captures only the sleep
# interval from stdout — not these log lines (which killed the loop when
# they landed in `sleep`). They still appear in `kubectl logs`.
log() { echo "[nginx-eqty-tls] $*" >&2; }
die() { echo "[nginx-eqty-tls] FATAL: $*" >&2; exit 1; }

# Flat top-level JSON string field extractor (no jq). Values we read
# (base64 cert blobs, condition strings) contain no escaped quotes.
json_str() {
  printf '%s' "$2" | tr -d '\n' \
    | sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

b64enc() { openssl base64 -A; }          # single-line, portable
b64dec() { openssl base64 -d -A; }

mkdir -p "$TLS_DIR" "$WELLKNOWN"

# ---- 1. key: generate once, in-guest, on tmpfs -----------------------
if [ ! -s "$TLS_DIR/tls.key" ]; then
  log "generating EC P-256 key in-guest at $TLS_DIR/tls.key"
  openssl ecparam -genkey -name prime256v1 -out "$TLS_DIR/tls.key"
  chmod 600 "$TLS_DIR/tls.key"
fi

# No bootstrap self-signed cert: we never present an invalid cert. nginx is
# started only after a real LE cert is installed (see the startup block at
# the bottom), so the pod stays not-ready during the ~30-90s issuance window
# instead of serving a cert clients would reject. The ACME HTTP-01 challenge
# is driven by cert-manager's external solver, not this nginx, so staying
# down blocks nothing.

# ---- kube API helpers (curl + SA token) ------------------------------
kube() {  # METHOD  PATH  [json-file]
  _m=$1; _p=$2; _d=${3:-}
  _tok="$(cat "$SA_DIR/token")"
  set -- -sS --cacert "$SA_DIR/ca.crt" \
        -H "Authorization: Bearer ${_tok}" -X "$_m"
  [ -n "$_d" ] && set -- "$@" -H 'Content-Type: application/json' --data-binary @"$_d"
  curl "$@" "${KUBE}${_p}"
}

# rc 0 if we should (re)request the LE cert: not yet LE-signed, or the
# current LE cert expires within RENEW_DAYS. Uses openssl -checkend so we
# don't depend on busybox `date` parsing openssl's date format.
needs_le_renewal() {
  cert_is_le || return 0
  openssl x509 -in "$TLS_DIR/tls.crt" -noout -checkend $(( RENEW_DAYS * 86400 )) >/dev/null 2>&1 && return 1
  return 0
}

# true if tls.crt was actually issued by an ACME CA (not our bootstrap
# self-signed): issuer != subject.
cert_is_le() {
  _s="$(openssl x509 -in "$TLS_DIR/tls.crt" -noout -subject 2>/dev/null)"
  _i="$(openssl x509 -in "$TLS_DIR/tls.crt" -noout -issuer  2>/dev/null)"
  [ "${_s#subject}" != "${_i#issuer}" ]
}

NS="$(cat "$SA_DIR/namespace" 2>/dev/null || echo default)"
CR_PATH="/apis/cert-manager.io/v1/namespaces/${NS}/certificaterequests"

# ---- 2. Let's Encrypt via a raw CertificateRequest -------------------
# Generates a CSR over our in-guest key, submits it, waits for
# cert-manager to drive the ACME order, installs the signed cert.
# Returns 0 and updates tls.crt on success.
request_le_cert() {
  log "building CSR over in-guest key for CN=${TLS_HOST}"
  openssl req -new -key "$TLS_DIR/tls.key" -subj "/CN=${TLS_HOST}" \
    -addext "subjectAltName=DNS:${TLS_HOST}" -out /tmp/le.csr

  _csr_b64="$(b64enc < /tmp/le.csr)"
  cat > /tmp/cr.json <<EOF
{"apiVersion":"cert-manager.io/v1","kind":"CertificateRequest",
 "metadata":{"name":"${CR_NAME}"},
 "spec":{"issuerRef":{"name":"${LE_ISSUER}","kind":"${LE_ISSUER_KIND}","group":"cert-manager.io"},
         "request":"${_csr_b64}"}}
EOF

  # fresh request each time: delete any prior CR (ignore 404), recreate
  kube DELETE "${CR_PATH}/${CR_NAME}" >/dev/null 2>&1 || true
  _resp="$(kube POST "${CR_PATH}" /tmp/cr.json)"
  case "$_resp" in
    *'"kind":"CertificateRequest"'*|*'"kind": "CertificateRequest"'*) : ;;
    *) log "CertificateRequest create rejected: $(printf '%s' "$_resp" | tr -d '\n' | cut -c1-200)"; return 1 ;;
  esac

  log "waiting for cert-manager to complete the ACME order"
  _i=0
  while [ "$_i" -lt 60 ]; do          # ~60 * POLL_INTERVAL
    _cr="$(kube GET "${CR_PATH}/${CR_NAME}")"
    _cert="$(json_str certificate "$_cr")"
    if [ -n "$_cert" ]; then
      printf '%s' "$_cert" | b64dec > /tmp/le.crt
      if openssl x509 -in /tmp/le.crt -noout 2>/dev/null; then
        cp /tmp/le.crt "$TLS_DIR/tls.crt"
        _ca="$(json_str ca "$_cr")"
        [ -n "$_ca" ] && printf '%s' "$_ca" | b64dec > "$TLS_DIR/ca.crt"
        log "LE cert installed (expires $(openssl x509 -in "$TLS_DIR/tls.crt" -noout -enddate | cut -d= -f2))"
        return 0
      fi
    fi
    case "$_cr" in
      *'"reason":"Denied"'*|*'"reason":"Failed"'*)
        log "CertificateRequest failed: $(printf '%s' "$_cr" | tr -d '\n' | sed -n 's/.*"message":"\([^"]*\)".*/\1/p' | cut -c1-160)"
        return 1 ;;
    esac
    _i=$((_i + 1)); sleep "$POLL_INTERVAL"
  done
  log "timed out waiting for LE cert"
  return 1
}

# ---- 3. notary cross-sign of the SAME in-guest key -------------------
# CSR over our key -> notary /v1/sign_cert -> bundle with the notary
# chain, published at $WELLKNOWN/notary-cross-sign.pem. Returns 0 on a
# fresh publish, 1 if the notary isn't ready / signing failed.
publish_cross_sign() {
  wget -q -O /dev/null "${NOTARY_URL}/v1/isReady" 2>/dev/null || { log "notary not ready"; return 1; }
  _tmp="${WELLKNOWN}/.tmp.$$"; rm -rf "$_tmp"; mkdir -p "$_tmp" || return 1

  _san="$(openssl x509 -in "$TLS_DIR/tls.crt" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' \n')"
  [ -n "$_san" ] || _san="DNS:${TLS_HOST}"
  # Distinct CN from the LE leaf (which is CN=${TLS_HOST}): both certs carry
  # the SAME public key, so a verifier that only glanced at the CN could
  # confuse the two. The notary leaf asserts TEE-binding, not domain control,
  # so mark it as such. Hostname stays in the SAN for anything that matches on it.
  openssl req -new -key "$TLS_DIR/tls.key" -subj "/CN=eqty-notary:${TLS_HOST}" \
    -addext "subjectAltName=${_san}" -out "${_tmp}/leaf.csr" || { rm -rf "$_tmp"; return 1; }

  # notary /v1/sign_cert wants {"csr": "<PEM>"}; PEM has no chars that
  # need JSON-escaping beyond newlines.
  _csr_json="$(awk 'NF{printf "%s\\n",$0}' "${_tmp}/leaf.csr")"
  printf '{"csr":"%s"}' "$_csr_json" > "${_tmp}/body.json"
  wget -q -O "${_tmp}/notary-leaf.pem" --header 'Content-Type: application/json' \
       --post-file "${_tmp}/body.json" "${NOTARY_URL}/v1/sign_cert" \
    || { log "notary sign_cert failed"; rm -rf "$_tmp"; return 1; }
  openssl x509 -in "${_tmp}/notary-leaf.pem" -noout 2>/dev/null \
    || { log "sign_cert did not return a certificate"; rm -rf "$_tmp"; return 1; }

  wget -q -O "${_tmp}/notary-chain.pem" "${NOTARY_URL}/v1/certificate_chain"        || { rm -rf "$_tmp"; return 1; }
  wget -q -O "${_tmp}/notary-ca.pem"    "${NOTARY_URL}/v1/certificate_chain?ca=true" || { rm -rf "$_tmp"; return 1; }
  openssl verify -CAfile "${_tmp}/notary-ca.pem" -untrusted "${_tmp}/notary-chain.pem" \
      "${_tmp}/notary-leaf.pem" >/dev/null \
    || { log "notary leaf does not verify against notary CA"; rm -rf "$_tmp"; return 1; }

  # bundle order: LE leaf+chain, notary leaf, notary chain, notary CA
  cat "$TLS_DIR/tls.crt" "${_tmp}/notary-leaf.pem" "${_tmp}/notary-chain.pem" \
      "${_tmp}/notary-ca.pem" > "${_tmp}/notary-cross-sign.pem"
  mv "${_tmp}/notary-cross-sign.pem" "${WELLKNOWN}/notary-cross-sign.pem"
  _spki="$(openssl pkey -in "$TLS_DIR/tls.key" -pubout -outform DER | openssl dgst -sha256 | sed 's/.*= *//')"
  rm -rf "$_tmp"
  log "published notary-cross-sign.pem (notary-leaf CN=eqty-notary:${TLS_HOST}, spki_sha256=${_spki})"
}

# ---- 4. serve nginx + renewal loop -----------------------------------
reconcile() {
  _changed=0
  if needs_le_renewal; then
    log "LE cert absent or within ${RENEW_DAYS}d of expiry — requesting"
    if request_le_cert; then _changed=1; else log "LE issuance failed; will retry"; fi
  fi
  # (re)publish the notary bundle whenever we have a real LE cert and
  # either it changed or no bundle exists yet.
  if cert_is_le && { [ "$_changed" = 1 ] || [ ! -s "${WELLKNOWN}/notary-cross-sign.pem" ]; }; then
    publish_cross_sign && _changed=1 || true
  fi
  [ "$_changed" = 1 ] && [ "$START_NGINX" = 1 ] && nginx -s reload 2>/dev/null || true
  # short cadence until we have a real LE cert, relaxed afterwards
  if cert_is_le; then echo "$IDLE_INTERVAL"; else echo "$POLL_INTERVAL"; fi
}

renewal_loop() {
  while :; do
    # reconcile prints ONLY the interval on stdout (logs go to stderr).
    # Guard against any stray output so a bad value can't kill the loop.
    _sleep="$(reconcile)" || true
    case "$_sleep" in ''|*[!0-9]*) _sleep=60 ;; esac
    sleep "$_sleep" || sleep 60
  done
}

if [ "$START_NGINX" = 1 ]; then
  # Block until a real LE cert exists BEFORE starting nginx. We never serve
  # the old bootstrap self-signed cert; the pod simply stays not-ready (its
  # tcpSocket readiness probe on :40443 fails while nginx is down) until the
  # attested cert is in place. Each reconcile() requests LE (its own internal
  # poll can take ~30-90s) and, once issued, publishes the notary bundle too,
  # so nginx comes up with both cert and cross-sign already present.
  log "waiting for Let's Encrypt cert before starting nginx (pod stays not-ready until then)"
  until cert_is_le; do
    reconcile >/dev/null || true
    cert_is_le || { log "LE cert not ready yet — retrying in ${POLL_INTERVAL}s"; sleep "$POLL_INTERVAL"; }
  done
  renewal_loop &                 # keep cert + bundle fresh alongside nginx
  log "LE cert present — starting nginx (serving :40443, TLS_HOST=${TLS_HOST})"
  exec nginx -g 'daemon off;'
else
  # unit-test / one-shot mode: single reconcile, no nginx
  reconcile >/dev/null
fi
