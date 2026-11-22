#!/usr/bin/env bash
# L3 lab — ENGAGEMENT-signed live scan producing COMMITTABLE evidence (TOOLS-4.2 L3
# formal promotion / QA-3). Unlike run.sh (which authorizes with a throw-away
# lab-policy), this authorizes with a signed ENGAGEMENT MANIFEST bound to an
# approver's Ed25519 key, and signs the run evidence — the provenance a formal
# live-tested promotion requires.
#
# Generic and secret-free: no key is baked in. The approver signing key and the
# evidence signing key are both generated at run time under ./.olympus/eng and
# are never committed; only the evidence JSON (+ .sig) and the approver PUBLIC
# key are meant to be kept/committed as the verifiable record.
#
# Scope note: the engagement manifest authorizes a *host* technique, so this
# runner targets nmap against a bare host/IP (manifest scope covers the host).
# httpx/nuclei scan URLs, which the host-scoped manifest does not cover; they
# stay on the lab-policy path (labs/l3/run.sh).
#
# The hardened container satisfies require_scanner_isolation(); do NOT relax the
# docker flags below — they are exactly what the live-scan gate checks.
#
# Prerequisites:
#   docker build -f docker/Dockerfile.scanners -t olympus-scanners .
#   docker network create olympuslab
#   docker run -d --name <target> --network olympuslab <authorized-target-image>
#
# Usage:  bash labs/l3/run_engagement.sh <TARGET-IP-or-HOST>
set -euo pipefail

ENGINE=nmap
TARGET="${1:-}"
IMAGE="${OLYMPUS_SCANNER_IMAGE:-olympus-scanners}"
NET="${OLYMPUS_LAB_NET:-olympuslab}"
CIDR="${OLYMPUS_LAB_CIDR:-172.18.0.0/16}"
ENG="$PWD/.olympus/eng"
OUT="$PWD/.olympus/out"

[ -n "$TARGET" ] || {
  echo "usage: run_engagement.sh <authorized target host or IP>" >&2
  exit 2
}
# nmap scans a host: the manifest scope covers the bare host, so target == host.
HOST_ONLY="${TARGET#http://}"
HOST_ONLY="${HOST_ONLY#https://}"
HOST_ONLY="${HOST_ONLY%%[:/]*}"

mkdir -p "$ENG" "$OUT"
chmod 777 "$OUT" # the unprivileged container user must be able to write the evidence
[ -f "$ENG/evidence_key.pem" ] || openssl genpkey -algorithm ed25519 -out "$ENG/evidence_key.pem"
# Export the evidence PUBLIC key: committing it lets a third party PIN-verify the
# signed evidence (olympus verify refuses an unpinned key). The private key stays
# local and is never committed.
openssl pkey -in "$ENG/evidence_key.pem" -pubout -out "$ENG/evidence_pub.pem"

# Generate the approver keypair and the signed engagement manifest, scoped to this
# host and authorizing the nmap technique for the next hour. This runs INSIDE the
# scanner image (which has olympus installed), so the host needs no olympus install;
# the files land in the mounted ./.olympus/eng, owned by the invoking user.
docker run --rm -i \
  --user "$(id -u):$(id -g)" \
  --entrypoint python3 \
  -e HOME=/tmp \
  -e OLYMPUS_ENG_HOST="$HOST_ONLY" \
  -v "$ENG:/eng" \
  "$IMAGE" \
  - <<'PY'
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from olympus.core.models import EngagementScope
from olympus.core.signing import generate_keypair
from olympus.engagements.manifest import EngagementManifest, SignedEngagementManifest

eng = Path("/eng")
host = os.environ["OLYMPUS_ENG_HOST"]
private_pem, public_pem = generate_keypair()
(eng / "approver_key.pem").write_text(private_pem, encoding="utf-8")
(eng / "approver_pub.pem").write_text(public_pem, encoding="utf-8")
now = datetime.now(UTC)
manifest = EngagementManifest(
    engagement_id="ENG-2026-00001",
    client="LAB",
    owner="LAB",
    approver="LAB",
    contract_id="LAB-L3",
    scope=EngagementScope(included=(host,)),
    valid_from=now - timedelta(minutes=1),
    expires_at=now + timedelta(hours=1),
    allowed_techniques=("nmap",),
    max_runtime_seconds=1800,
)
signed = SignedEngagementManifest.sign_manifest(manifest, private_key_pem=private_pem)
(eng / "signed-manifest.json").write_text(signed.model_dump_json(indent=2), encoding="utf-8")
print(f"signed engagement manifest {signed.manifest_sha256[:12]} for host {host}")
PY

# Themis scope file: the engagement manifest authorizes the engagement, but
# `themis run` additionally requires a versioned scope authorizing the target.
# Listing the host (and the lab CIDR) is what lets resolve_and_validate() reach a
# private lab IP — no lab policy needed, and no extra required-CIDR constraint.
cat > "$ENG/scope.json" <<JSON
{"schema_name":"olympus.themis-scope","schema_version":"1.0.0","allowed_hosts":["$HOST_ONLY"],"allowed_domains":[],"allowed_cidrs":["$CIDR"]}
JSON

chmod -R a+rX "$ENG"

# The isolation flags below are what require_scanner_isolation() verifies; never relax them.
# `themis run` uses findings-aware exit codes: 0 = ok, 1 = findings found, 5 = partial
# — the scan executed in all three. Capture the code so `set -e` does not abort the
# run (and skip the evidence read-back) just because nmap reported an open port.
scan_rc=0
docker run --rm \
  --network "$NET" \
  --user 10001:10001 \
  --read-only --tmpfs /tmp:rw,mode=1777 --tmpfs /data:rw,mode=1777 --tmpfs /store:rw,mode=1777 \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  -e HOME=/tmp \
  -e THEMIS_ENABLE_LIVE_SCANS=true \
  -e OLYMPUS_EVIDENCE_SIGNING_KEY_FILE=/eng/evidence_key.pem \
  -v "$ENG:/eng:ro" \
  -v "$OUT:/out" \
  "$IMAGE" \
  themis run "$ENGINE" --target "$HOST_ONLY" --kind host \
    --scope /eng/scope.json \
    --signed-manifest /eng/signed-manifest.json \
    --manifest-public-key /eng/approver_pub.pem \
    --engagement-storage /store \
    --i-am-authorized \
    --evidence "/out/$ENGINE-engagement-evidence.json" \
    --output "/out/$ENGINE-engagement-result.json" \
    --timeout 300 --deadline 400 || scan_rc=$?

case "$scan_rc" in
  0 | 1 | 5) ;; # ok / findings found / partial — the scan ran and wrote evidence
  *)
    echo "olympus: scan failed (exit $scan_rc); no evidence to read back" >&2
    exit "$scan_rc"
    ;;
esac

# The scan ran as the unprivileged 10001 user and wrote the evidence 0600, owned by
# that uid — unreadable by the operator who must commit it. A tiny throwaway,
# no-network container running AS THE SAME uid (the files' owner) relaxes the read
# bits so the host operator can read the signed evidence. Owner chmod needs no
# capabilities (hence --cap-drop ALL holds), and it never touches the scan
# container's isolation — only the already-produced evidence files.
docker run --rm \
  --user 10001:10001 \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  --entrypoint chmod \
  -v "$OUT:/out" \
  "$IMAGE" \
  a+r "/out/$ENGINE-engagement-evidence.json" \
      "/out/$ENGINE-engagement-evidence.json.sig" \
      "/out/$ENGINE-engagement-result.json"

echo "L3 engagement-signed done:"
echo "  evidence : $OUT/$ENGINE-engagement-evidence.json (+ .sig)"
echo "  evidence public key (pin for verification): $ENG/evidence_pub.pem"
echo "  approver public key (engagement authorization): $ENG/approver_pub.pem"
echo "  signed manifest: $ENG/signed-manifest.json"
