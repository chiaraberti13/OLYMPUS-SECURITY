#!/usr/bin/env bash
# Provision a protected, offline Olympus engine lab.
#
# Installs the three mandatory engines at the EXACT manifest pins (the same
# recipe as docker/Dockerfile.scanners), the nuclei-templates data dependency at
# its pinned commit, and a loopback-only target plus an authorization scope and a
# lab policy bounded to a documentation CIDR. Everything is served and scanned on
# a host-local documentation address (TEST-NET-1, 192.0.2.0/24): no real network
# target is ever contacted, so the scan is authorized in-scope by construction.
#
# What this unblocks, verified by tests/unit/test_lab_provision.py:
#   * L1 (presence/version/commit) + L2 (probe in the runtime sandbox) via
#     `olympus engines doctor` -> exit 0 for nmap/nuclei/httpx.
#   * Direct engine runs (e.g. `nuclei -u http://192.0.2.X:PORT -t .../http/exposures/`).
#
# What this does NOT grant: L3 signed-evidence live `themis run` execution. That
# is gated by require_scanner_isolation() on the hardened scanner container
# (read-only root, seccomp, empty capabilities, pinned-image attestation) and can
# only run inside docker/Dockerfile.scanners + the compose overlay — never in a
# plain shell. See docs/engines/LAB.md.
#
# Pins below MIRROR src/olympus/engines/<name>/engine.toml and
# src/olympus/engines/_data/nuclei-templates.toml; the drift test fails if they
# disagree, exactly like tests/unit/test_engine_dockerfile_pins.py for the image.
set -euo pipefail

LAB=/opt/olympus-lab
HTTPX_VERSION=v1.11.0
NUCLEI_VERSION=v3.11.1
NMAP_COMMIT=0ee561663c1d7d2d4e708cd414dccfd3d9df30d9
TPL_COMMIT=79fb682760ab3d5b0e22afbb44709353cbebf023

mkdir -p "$LAB/bin" "$LAB/src"
export GOBIN="$LAB/bin"

# -- Go engines at the manifest pins --
if [ ! -x "$LAB/bin/httpx" ]; then
  go install "github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}"
fi
if [ ! -x "$LAB/bin/nuclei" ]; then
  go install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}"
fi

# -- nmap built from the pinned commit (v7.992), same recipe as Dockerfile.scanners.
#    The source checkout stays at /opt/nmap: `engines doctor` rev-parses it. --
if [ ! -d /opt/nmap/.git ]; then
  git init -q /opt/nmap
  git -C /opt/nmap fetch -q --depth 1 https://github.com/nmap/nmap "$NMAP_COMMIT"
  git -C /opt/nmap checkout -q --detach FETCH_HEAD
  test "$(git -C /opt/nmap rev-parse HEAD)" = "$NMAP_COMMIT"
fi
if [ ! -x "$LAB/bin/nmap" ]; then
  cd /opt/nmap
  find . -name configure -type f -exec touch {} +
  CFG="--without-zenmap --without-ndiff --without-nping --without-ncat --without-nmap-update"
  ./configure --prefix="$LAB" $CFG >/dev/null
  make -j"$(nproc)" >/dev/null
  make install >/dev/null
  cd /
fi

# -- nuclei-templates at the pinned commit, at the path the manifest expects --
if [ ! -d /opt/nuclei-templates/.git ]; then
  git init -q /opt/nuclei-templates
  git -C /opt/nuclei-templates fetch -q --depth 1 \
    https://github.com/projectdiscovery/nuclei-templates "$TPL_COMMIT"
  git -C /opt/nuclei-templates checkout -q --detach FETCH_HEAD
fi

# -- expose the pinned engines on PATH (shadows the base image's python 'httpx') --
ln -sf "$LAB/bin/httpx" /usr/local/bin/httpx
ln -sf "$LAB/bin/nuclei" /usr/local/bin/nuclei
ln -sf "$LAB/bin/nmap" /usr/local/bin/nmap

# -- loopback target: files that trigger real nuclei http/exposures detections.
#    Bind the server to a host-local documentation address so the Olympus lab
#    policy (which forbids loopback/public, allows owned private/doc ranges)
#    accepts it; 192.0.2.0/24 is TEST-NET-1 and never routes off-host. --
T="$LAB/target"
mkdir -p "$T/.git"
printf '[core]\n\trepositoryformatversion = 0\n\tbare = false\n' > "$T/.git/config"
printf 'DB_PASSWORD=labonly-not-a-secret\nAPI_KEY=lab-placeholder-0000\n' > "$T/.env"
printf '<?php phpinfo(); ?>\n' > "$T/info.php"
printf 'User-agent: *\nDisallow: /admin\nDisallow: /.git\n' > "$T/robots.txt"
chmod -R a+rX "$LAB"

# -- authorization scope + lab policy bounded to the documentation CIDR --
cat > "$LAB/scope.json" <<'JSON'
{"schema_name":"olympus.themis-scope","schema_version":"1.0.0","allowed_hosts":["192.0.2.2"],"allowed_domains":[],"allowed_cidrs":["192.0.2.0/24"]}
JSON
cat > "$LAB/lab.toml" <<'TOML'
schema_version = "1.0.0"
engagement = "LAB-OLYMPUS-DOC-NET-01"
[lab]
enabled = true
allowed_networks = ["192.0.2.0/24"]
activated_by = "olympus-lab"
activated_at = 2026-11-21T00:00:00Z
TOML

echo "olympus-lab ready: engines $LAB/bin, templates /opt/nuclei-templates, target $T"
echo "L1/L2 : olympus engines doctor            # expect exit 0 (all mandatory present)"
echo "serve : python3 -m http.server 8080 --bind 192.0.2.2 --directory $T"
echo "scan  : nuclei -u http://192.0.2.2:8080 -t /opt/nuclei-templates/http/exposures/"
