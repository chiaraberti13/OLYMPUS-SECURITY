#!/usr/bin/env bash
# Compatibility name for installing the maintained native THEMIS runtime.
set -Eeuo pipefail

TASK_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TASK_PYTHON="${PYTHON:-python3}"

"$TASK_PYTHON" -m pip install -e "$TASK_REPO_ROOT[themis,dev]"
echo "Native THEMIS installed. See docs/themis-runtime.md for scopes, identities and TLS."
echo "Scanner binaries are installed independently or through docker/Dockerfile.scanners."
