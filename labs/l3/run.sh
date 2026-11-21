#!/usr/bin/env bash
# L3 lab — run a mandatory engine LIVE inside the hardened scanner container,
# against an authorized private target, producing SIGNED evidence (TOOLS-4.2 L3).
#
# Generic and secret-free: no keys or targets are baked in. The engagement HMAC key
# comes from the environment (OLYMPUS_POLICY_LAB_KEY), the Ed25519 evidence key is
# generated at run time under ./.olympus/lab, and the target is a host/URL you pass.
#
# The hardened container satisfies require_scanner_isolation(): read-only root, empty
# capabilities, no-new-privileges, seccomp and the pinned scanner-image attestation.
# Do NOT relax the docker flags below — they are exactly what the live-scan gate checks.
#
# Prerequisites:
#   docker build -f docker/Dockerfile.scanners -t olympus-scanners .
#   docker network create olympuslab
#   docker run -d --name <target> --network olympuslab <some-authorized-target-image>
#   export OLYMPUS_POLICY_LAB_KEY="<a random string of at least 32 bytes>"
#
# Usage:  bash labs/l3/run.sh [nmap|httpx|nuclei] <TARGET-IP-or-URL>
set -euo pipefail

ENGINE="${1:-nmap}"
TARGET="${2:-}"
IMAGE="${OLYMPUS_SCANNER_IMAGE:-olympus-scanners}"
NET="${OLYMPUS_LAB_NET:-olympuslab}"
CIDR="${OLYMPUS_LAB_CIDR:-172.18.0.0/16}"
LAB="$PWD/.olympus/lab"
OUT="$PWD/.olympus/out"

: "${OLYMPUS_POLICY_LAB_KEY:?set OLYMPUS_POLICY_LAB_KEY to a random lab HMAC key of >=32 bytes}"

case "$ENGINE" in
  nmap | httpx | nuclei) ;;
  *)
    echo "engine must be nmap, httpx or nuclei" >&2
    exit 2
    ;;
esac
[ -n "$TARGET" ] || {
  echo "usage: run.sh [nmap|httpx|nuclei] <authorized target IP or URL>" >&2
  exit 2
}

# nmap scans a host; httpx/nuclei scan a URL.
if [ "$ENGINE" = "nmap" ]; then
  KIND=host
  SCAN_TARGET="$TARGET"
else
  KIND=url
  case "$TARGET" in
    http://* | https://*) SCAN_TARGET="$TARGET" ;;
    *) SCAN_TARGET="http://$TARGET" ;;
  esac
fi
HOST_ONLY="${SCAN_TARGET#http://}"
HOST_ONLY="${HOST_ONLY#https://}"
HOST_ONLY="${HOST_ONLY%%[:/]*}"

mkdir -p "$LAB" "$OUT"
chmod 777 "$OUT" # the unprivileged container user must be able to write the evidence
[ -f "$LAB/evidence_key.pem" ] || openssl genpkey -algorithm ed25519 -out "$LAB/evidence_key.pem"

cat > "$LAB/scope.json" <<JSON
{"schema_name":"olympus.themis-scope","schema_version":"1.0.0","allowed_hosts":["$HOST_ONLY"],"allowed_domains":[],"allowed_cidrs":["$CIDR"]}
JSON
cat > "$LAB/lab.toml" <<TOML
schema_version = "1.0.0"
engagement = "LAB-DOCKER-L3"
[lab]
enabled = true
allowed_networks = ["$CIDR"]
activated_by = "lab"
activated_at = 2026-11-21T00:00:00Z
TOML
chmod -R a+rX "$LAB"

# The isolation flags below are what require_scanner_isolation() verifies; never relax them.
docker run --rm \
  --network "$NET" \
  --user 10001:10001 \
  --read-only --tmpfs /tmp:rw,mode=1777 --tmpfs /data:rw,mode=1777 \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  -e HOME=/tmp \
  -e THEMIS_ENABLE_LIVE_SCANS=true \
  -e OLYMPUS_POLICY_LAB_KEY \
  -e OLYMPUS_EVIDENCE_SIGNING_KEY_FILE=/lab/evidence_key.pem \
  -v "$LAB:/lab:ro" \
  -v "$OUT:/out" \
  "$IMAGE" \
  themis run "$ENGINE" --target "$SCAN_TARGET" --kind "$KIND" \
    --scope /lab/scope.json --lab-policy /lab/lab.toml --i-am-authorized \
    --evidence "/out/$ENGINE-evidence.json" --output "/out/$ENGINE-result.json" \
    --timeout 300 --deadline 400

echo "L3 done: signed evidence at $OUT/$ENGINE-evidence.json (+ .sig)"
