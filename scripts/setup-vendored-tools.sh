#!/usr/bin/env bash
# Temporary compatibility setup for the vendored VAP runtime.
#
# External *scanner binaries* used
# by VAP (nmap, nuclei, sqlmap, wpscan, ...) are installed separately by the
# VAP installer or provided by its Docker image — see the notes at the end.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"

echo "==> Installing Olympus (editable) with the temporary THEMIS web extra"
"$PYTHON" -m pip install -e "$ROOT[themis,dev]"

echo "==> Installing the complete VAP pinned requirements"
"$PYTHON" -m pip install -r "$ROOT/vendor/vulnerability-assessment-platform/requirements.txt"

echo
echo "Done. Run the tools through Olympus:"
echo "  olympus argus --help                 # native ARGUS workflows"
echo "  olympus themis scanners                 # list all 24 scanners"
echo "  olympus themis migrate                  # apply THEMIS DB migrations"
echo "  olympus themis serve --host 127.0.0.1 --port 8000   # serve the THEMIS web app"
echo
echo "External scanner binaries (nmap, nuclei, sqlmap, wpscan, ...) and the full"
echo "stack (Redis/Celery for queued scans) are provisioned reproducibly by:"
echo "  bash vendor/vulnerability-assessment-platform/installer.sh"
echo "  docker compose -f vendor/vulnerability-assessment-platform/docker-compose.yml up"
