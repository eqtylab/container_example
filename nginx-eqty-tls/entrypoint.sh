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
# LE_ISSUER=none drops steps 2's cert-manager round trip: the notary signs
# our CSR directly and its leaf becomes the serving cert. Steps 1 and 3 are
# unchanged, so the key is still born in the guest — see README.md for the
# trust trade-off.
#
# Tooling: /bin/sh (busybox), curl, wget from nginx:alpine + openssl
# added by the Dockerfile. No jq, no kubectl — the Kubernetes API is
# driven with curl + the pod's ServiceAccount token.
set -eu

TLS_HOST="${TLS_HOST:?TLS_HOST (public DNS name) is required}"
TLS_DIR="${TLS_DIR:-/tls}"
WELLKNOWN="${WELLKNOWN:-/var/www/wellknown}"
NOTARY_URL="${NOTARY_URL:-http://127.0.0.1:8066}"
# LE_ISSUER=none turns the cert-manager path off entirely: no CertificateRequest
# is submitted and the Kubernetes API is never contacted. The notary becomes the
# CA — it signs a CSR over our in-guest key exactly as the ACME issuer would, so
# the key is still generated here and still never leaves the guest. The trade is
# public trust: clients must trust the notary CA, which the ones verifying the
# attestation binding already do. A cert+key supplied by the deployment (mounted
# Secret) is honoured instead of signing, and gets cross-signed as usual.
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

# LE_ISSUER=none -> the notary is the CA; skip everything cert-manager.
le_enabled() { [ "$LE_ISSUER" != none ]; }

mkdir -p "$TLS_DIR" "$WELLKNOWN"

# ---- 1. key: generate once, in-guest, on tmpfs -----------------------
le_enabled || log "LE_ISSUER=none — cert-manager disabled; the notary signs our CSR"
# Both modes need this key: cert-manager and the notary sign the same kind of
# CSR over it. Skipped only when the deployment supplied its own pair.
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
  le_enabled || return 1
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

# A parseable cert whose public key is the one in tls.key. cert_is_le()'s
# issuer != subject test can't serve as the notary-mode gate — a supplied cert
# may legitimately be self-signed — so we check the pairing instead, which also
# catches the mismatched-mount case nginx would otherwise die on at startup.
cert_usable() {
  [ -s "$TLS_DIR/tls.crt" ] && [ -s "$TLS_DIR/tls.key" ] || return 1
  _ck="$(openssl x509 -in "$TLS_DIR/tls.crt" -noout -pubkey 2>/dev/null)" || return 1
  _kk="$(openssl pkey  -in "$TLS_DIR/tls.key" -pubout     2>/dev/null)" || return 1
  [ -n "$_ck" ] && [ "$_ck" = "$_kk" ]
}

# Did WE get tls.crt from the notary? Both issuance paths write ca.crt, so that
# file can't tell them apart — hence an explicit marker. It decides whether the
# published bundle needs a separate cross-signature (see publish_cross_sign).
NOTARY_MARK="${TLS_DIR}/.notary-issued"
cert_from_notary() { [ -f "$NOTARY_MARK" ]; }

# "we hold a cert worth serving", whichever mode we are in.
cert_ready() {
  if le_enabled; then cert_is_le; else cert_usable; fi
}

# rc 0 if we should ask the notary for a serving cert: nothing serveable yet,
# or ours is close to expiry. A cert the deployment supplied is left alone —
# we only cross-sign that one, never overwrite it.
needs_notary_cert() {
  if le_enabled; then return 1; fi
  cert_usable || return 0
  cert_from_notary || return 1
  openssl x509 -in "$TLS_DIR/tls.crt" -noout -checkend $(( RENEW_DAYS * 86400 )) >/dev/null 2>&1 && return 1
  return 0
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
        rm -f "$NOTARY_MARK"
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

# ---- 3. notary signing of the in-guest key ---------------------------
# CSR over our key -> notary /v1/sign_cert, plus the notary chain and CA,
# verified together. Writes notary-leaf.pem, notary-chain.pem and
# notary-ca.pem into the caller's scratch dir $1 (the caller cleans it up).
#
# This needs tls.key and nothing else: the notary signs a CSR exactly as the
# ACME CA does, so it works with no pre-existing certificate. That is what
# lets LE_ISSUER=none serve a notary-signed cert instead of an LE one.
notary_sign() {
  _tmp="$1"
  wget -q -O /dev/null "${NOTARY_URL}/v1/isReady" 2>/dev/null || { log "notary not ready"; return 1; }

  # Carry over the SAN of the cert we already serve; on a first boot in
  # notary-only mode there is none yet, so TLS_HOST is all we have.
  _san="$(openssl x509 -in "$TLS_DIR/tls.crt" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' \n')"
  [ -n "$_san" ] || _san="DNS:${TLS_HOST}"
  # Distinct CN from the LE leaf (which is CN=${TLS_HOST}): both certs carry
  # the SAME public key, so a verifier that only glanced at the CN could
  # confuse the two. The notary leaf asserts TEE-binding, not domain control,
  # so mark it as such. Hostname stays in the SAN for anything that matches on
  # it — including TLS clients, when this leaf is also the serving cert.
  openssl req -new -key "$TLS_DIR/tls.key" -subj "/CN=eqty-notary:${TLS_HOST}" \
    -addext "subjectAltName=${_san}" -out "${_tmp}/leaf.csr" || return 1

  # notary /v1/sign_cert wants {"csr": "<PEM>"}; PEM has no chars that
  # need JSON-escaping beyond newlines.
  _csr_json="$(awk 'NF{printf "%s\\n",$0}' "${_tmp}/leaf.csr")"
  printf '{"csr":"%s"}' "$_csr_json" > "${_tmp}/body.json"
  wget -q -O "${_tmp}/notary-leaf.pem" --header 'Content-Type: application/json' \
       --post-file "${_tmp}/body.json" "${NOTARY_URL}/v1/sign_cert" \
    || { log "notary sign_cert failed"; return 1; }
  openssl x509 -in "${_tmp}/notary-leaf.pem" -noout 2>/dev/null \
    || { log "sign_cert did not return a certificate"; return 1; }

  wget -q -O "${_tmp}/notary-chain.pem" "${NOTARY_URL}/v1/certificate_chain"        || return 1
  wget -q -O "${_tmp}/notary-ca.pem"    "${NOTARY_URL}/v1/certificate_chain?ca=true" || return 1
  openssl verify -CAfile "${_tmp}/notary-ca.pem" -untrusted "${_tmp}/notary-chain.pem" \
      "${_tmp}/notary-leaf.pem" >/dev/null \
    || { log "notary leaf does not verify against notary CA"; return 1; }
}

# LE_ISSUER=none: take the serving cert from the notary itself. Same in-guest
# key, same CSR flow as the ACME path — only the CA differs. tls.crt becomes
# leaf + notary chain so nginx serves a complete path to the notary CA, which
# clients must trust. Returns 0 and updates tls.crt on success.
request_notary_cert() {
  _d="${TLS_DIR}/.tmp.$$"; rm -rf "$_d"; mkdir -p "$_d" || return 1
  notary_sign "$_d" || { rm -rf "$_d"; return 1; }
  cat "${_d}/notary-leaf.pem" "${_d}/notary-chain.pem" > "${_d}/serving.pem" \
    || { rm -rf "$_d"; return 1; }
  cp "${_d}/notary-ca.pem" "$TLS_DIR/ca.crt"
  mv "${_d}/serving.pem" "$TLS_DIR/tls.crt"
  : > "$NOTARY_MARK"
  rm -rf "$_d"
  log "notary cert installed (expires $(openssl x509 -in "$TLS_DIR/tls.crt" -noout -enddate | cut -d= -f2))"
}

# Publish the public bundle at $WELLKNOWN/notary-cross-sign.pem. Returns 0 on
# a fresh publish, 1 if the notary isn't ready / signing failed.
publish_cross_sign() {
  _t="${WELLKNOWN}/.tmp.$$"; rm -rf "$_t"; mkdir -p "$_t" || return 1
  if cert_from_notary; then
    # The notary already signed the key we serve, so tls.crt IS the notary
    # leaf + chain and ca.crt the notary CA. Assemble from those rather than
    # burning a second signature on a leaf that would only duplicate it.
    cat "$TLS_DIR/tls.crt" "$TLS_DIR/ca.crt" > "${_t}/bundle.pem" \
      || { log "cannot assemble bundle from notary-issued cert"; rm -rf "$_t"; return 1; }
  else
    # Cert came from elsewhere (cert-manager, or supplied by the deployment):
    # cross-sign the same key. Bundle order: leaf+chain, notary leaf, notary
    # chain, notary CA.
    notary_sign "$_t" || { rm -rf "$_t"; return 1; }
    cat "$TLS_DIR/tls.crt" "${_t}/notary-leaf.pem" "${_t}/notary-chain.pem" \
        "${_t}/notary-ca.pem" > "${_t}/bundle.pem" || { rm -rf "$_t"; return 1; }
  fi
  mv "${_t}/bundle.pem" "${WELLKNOWN}/notary-cross-sign.pem"
  _spki="$(openssl pkey -in "$TLS_DIR/tls.key" -pubout -outform DER | openssl dgst -sha256 | sed 's/.*= *//')"
  rm -rf "$_t"
  log "published notary-cross-sign.pem (notary-leaf CN=eqty-notary:${TLS_HOST}, spki_sha256=${_spki})"
}

# ---- 4. serve nginx + renewal loop -----------------------------------
reconcile() {
  _changed=0
  if needs_le_renewal; then
    log "LE cert absent or within ${RENEW_DAYS}d of expiry — requesting"
    if request_le_cert; then _changed=1; else log "LE issuance failed; will retry"; fi
  elif needs_notary_cert; then
    log "notary cert absent or within ${RENEW_DAYS}d of expiry — requesting"
    if request_notary_cert; then _changed=1; else log "notary issuance failed; will retry"; fi
  fi
  # (re)publish the notary bundle whenever we have a usable cert and either it
  # changed, no bundle exists yet, or the cert on disk is newer than the bundle
  # we last built from it — which covers a supplied Secret rotated under us,
  # and an LE renewal whose publish failed because the notary was down.
  if cert_ready && { [ "$_changed" = 1 ] || [ ! -s "${WELLKNOWN}/notary-cross-sign.pem" ] \
       || [ "$TLS_DIR/tls.crt" -nt "${WELLKNOWN}/notary-cross-sign.pem" ]; }; then
    publish_cross_sign && _changed=1 || true
  fi
  [ "$_changed" = 1 ] && [ "$START_NGINX" = 1 ] && nginx -s reload 2>/dev/null || true
  # short cadence until we have a usable cert, relaxed afterwards
  if cert_ready; then echo "$IDLE_INTERVAL"; else echo "$POLL_INTERVAL"; fi
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
  if le_enabled; then
    log "waiting for Let's Encrypt cert before starting nginx (pod stays not-ready until then)"
  else
    log "waiting for a notary-signed cert before starting nginx (pod stays not-ready until then)"
  fi
  until cert_ready; do
    reconcile >/dev/null || true
    cert_ready || { log "cert not ready yet — retrying in ${POLL_INTERVAL}s"; sleep "$POLL_INTERVAL"; }
  done
  renewal_loop &                 # keep cert + bundle fresh alongside nginx
  log "cert present — starting nginx (serving :40443, TLS_HOST=${TLS_HOST})"
  exec nginx -g 'daemon off;'
else
  # unit-test / one-shot mode: single reconcile, no nginx
  reconcile >/dev/null
fi
