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

chmod -R a+rX "$ENG"

# The isolation flags below are what require_scanner_isolation() verifies; never relax them.
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
    --signed-manifest /eng/signed-manifest.json \
    --manifest-public-key /eng/approver_pub.pem \
    --engagement-storage /store \
    --i-am-authorized \
    --evidence "/out/$ENGINE-engagement-evidence.json" \
    --output "/out/$ENGINE-engagement-result.json" \
    --timeout 300 --deadline 400

echo "L3 engagement-signed done:"
echo "  evidence : $OUT/$ENGINE-engagement-evidence.json (+ .sig)"
echo "  approver public key (for verification): $ENG/approver_pub.pem"
echo "  signed manifest: $ENG/signed-manifest.json"
