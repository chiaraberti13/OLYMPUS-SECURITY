"""Registry of the 24 AEGIS (vendored VAP) scanner integrations.

This is the Olympus-native source of truth for *what each scanner needs to run
for real*: its external executable (or API), licence, whether it is
redistributable/installable automatically, how to install it, and whether the
scanner-enabled container image bundles it. It drives ``olympus aegis
scanners``, ``olympus aegis deps``, and the ``doctor`` diagnostics.

Important honesty note: the vendored platform ships each scanner with a
**simulated** default mode (hard-coded educational findings) that is used unless
``VAP_ENABLE_LIVE_SCANS=true`` AND the scanner's binary/API is available. Live
execution is therefore gated on (1) explicit opt-in, (2) the dependency below
being present, and (3) authorization/scope. Simulated output is never counted
here as a working live scan.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class ScannerSpec:
    """Everything Olympus needs to know to run one vendored scanner for real."""

    name: str
    purpose: str
    category: str
    #: External executable checked with ``shutil.which``; ``None`` for API/daemon engines.
    binary: str | None
    licence: str
    #: True if the tool can be redistributed / installed automatically (OSS).
    redistributable: bool
    #: How to install it in a reproducible environment.
    install: str
    #: Whether docker/Dockerfile.scanners bundles it by default.
    in_scanner_image: bool

    def available(self) -> bool:
        """Return True if the scanner's binary is on PATH (API engines: unknown → False)."""
        return bool(self.binary and shutil.which(self.binary))

    @property
    def kind(self) -> str:
        """Deployment/licensing class (see ``KIND``)."""
        return KIND[self.name]


# Deployment/licensing class per scanner. ZAP and OpenVAS/GVM are open source
# and must not be grouped with the commercial engines.
KIND: dict[str, str] = {
    # local OSS CLI binaries
    "nmap": "local-oss-binary",
    "nikto": "local-oss-binary",
    "whatweb": "local-oss-binary",
    "wafw00f": "local-oss-binary",
    "sqlmap": "local-oss-binary",
    "arjun": "local-oss-binary",
    "wapiti": "local-oss-binary",
    "commix": "local-oss-binary",
    "xsstrike": "local-oss-binary",
    "dirsearch": "local-oss-binary",
    "nosqlmap": "local-oss-binary",
    "nuclei": "local-oss-binary",
    "httpx": "local-oss-binary",
    "katana": "local-oss-binary",
    "subfinder": "local-oss-binary",
    "dalfox": "local-oss-binary",
    "testssl": "local-oss-binary",
    "theharvester": "local-oss-binary",
    # source-available (non-OSI) local binary; free with a token for the vuln DB
    "wpscan": "local-oss-binary",
    # OSS engines that run as a long-lived service / daemon with an API
    "zap": "containerised-oss-service",
    "openvas": "containerised-oss-service",
    # proprietary, licensed engines exposed via API/app
    "nessus": "proprietary-remote-api",
    "acunetix": "proprietary-remote-api",
    "burp": "proprietary-local",
}


# The complete catalogue — all 24 integrations. Binary names match the vendored
# scanners' shutil.which(...) / settings.*_path defaults.
REGISTRY: tuple[ScannerSpec, ...] = (
    ScannerSpec(
        "nmap",
        "Network port & service enumeration",
        "network",
        "nmap",
        "GPL-2.0",
        True,
        "apt-get install nmap",
        True,
    ),
    ScannerSpec(
        "nikto",
        "Web server misconfiguration scan",
        "web",
        "nikto",
        "GPL-2.0",
        True,
        "apt-get install nikto",
        True,
    ),
    ScannerSpec(
        "whatweb",
        "Web technology fingerprinting",
        "web",
        "whatweb",
        "GPL-3.0",
        True,
        "apt-get install whatweb",
        True,
    ),
    ScannerSpec(
        "wafw00f",
        "WAF detection",
        "web",
        "wafw00f",
        "BSD-3-Clause",
        True,
        "pip install wafw00f",
        True,
    ),
    ScannerSpec(
        "sqlmap",
        "SQL injection detection/exploitation",
        "web",
        "sqlmap",
        "GPL-2.0",
        True,
        "pip install sqlmap (VAP_SQLMAP_PATH)",
        True,
    ),
    ScannerSpec(
        "arjun",
        "HTTP parameter discovery",
        "web",
        "arjun",
        "AGPL-3.0",
        True,
        "pip install arjun",
        True,
    ),
    ScannerSpec(
        "wapiti",
        "Web application vulnerability scan",
        "web",
        "wapiti",
        "GPL-2.0",
        True,
        "pip install wapiti3 (VAP_WAPITI_PATH)",
        True,
    ),
    ScannerSpec(
        "commix",
        "Command-injection detection",
        "web",
        "commix",
        "GPL-3.0",
        True,
        "pip install commix (VAP_COMMIX_PATH)",
        True,
    ),
    ScannerSpec(
        "xsstrike",
        "XSS detection",
        "web",
        "xsstrike",
        "GPL-3.0",
        True,
        "git clone XSStrike (VAP_XSSTRIKE_PATH)",
        True,
    ),
    ScannerSpec(
        "dirsearch",
        "Content/path discovery",
        "web",
        "dirsearch",
        "GPL-2.0",
        True,
        "pip install dirsearch (VAP_DIRSEARCH_PATH)",
        True,
    ),
    ScannerSpec(
        "nosqlmap",
        "NoSQL injection detection",
        "web",
        "nosqlmap",
        "GPL-3.0",
        True,
        "git clone NoSQLMap",
        True,
    ),
    ScannerSpec(
        "nuclei",
        "Template-based vulnerability scan",
        "web",
        "nuclei",
        "MIT",
        True,
        "go install github.com/projectdiscovery/nuclei",
        True,
    ),
    ScannerSpec(
        "httpx",
        "Fast HTTP probing/toolkit",
        "web",
        "httpx",
        "MIT",
        True,
        "go install github.com/projectdiscovery/httpx",
        True,
    ),
    ScannerSpec(
        "katana",
        "Crawling / endpoint discovery",
        "web",
        "katana",
        "MIT",
        True,
        "go install github.com/projectdiscovery/katana",
        True,
    ),
    ScannerSpec(
        "subfinder",
        "Passive subdomain enumeration",
        "dns",
        "subfinder",
        "MIT",
        True,
        "go install github.com/projectdiscovery/subfinder",
        True,
    ),
    ScannerSpec(
        "dalfox",
        "XSS scanning/parameter analysis",
        "web",
        "dalfox",
        "MIT",
        True,
        "go install github.com/hahwul/dalfox",
        True,
    ),
    ScannerSpec(
        "testssl",
        "TLS/SSL configuration analysis",
        "tls",
        "testssl.sh",
        "GPL-2.0",
        True,
        "git clone testssl.sh",
        True,
    ),
    ScannerSpec(
        "theharvester",
        "OSINT email/subdomain harvesting",
        "dns",
        "theHarvester",
        "GPL-2.0",
        True,
        "pip install theHarvester",
        True,
    ),
    ScannerSpec(
        "wpscan",
        "WordPress vulnerability scan",
        "web",
        "wpscan",
        "WPScan Public Source (non-OSI)",
        False,
        "gem install wpscan (free token required for the vuln DB)",
        True,
    ),
    ScannerSpec(
        "zap",
        "OWASP ZAP DAST (API/daemon)",
        "web",
        None,
        "Apache-2.0",
        True,
        "OWASP ZAP daemon / docker image (API-driven)",
        False,
    ),
    ScannerSpec(
        "openvas",
        "OpenVAS/GVM network vulnerability scan",
        "vuln",
        None,
        "GPL-2.0",
        True,
        "Greenbone GVM stack (heavy; docker/manual, API-driven)",
        False,
    ),
    ScannerSpec(
        "nessus",
        "Tenable Nessus vulnerability scan",
        "vuln",
        None,
        "Commercial (Tenable)",
        False,
        "Manual install + licence (API-driven)",
        False,
    ),
    ScannerSpec(
        "burp",
        "PortSwigger Burp Suite (Pro API)",
        "web",
        None,
        "Commercial (PortSwigger)",
        False,
        "Manual install + licence (API-driven)",
        False,
    ),
    ScannerSpec(
        "acunetix",
        "Invicti/Acunetix DAST",
        "web",
        None,
        "Commercial (Invicti)",
        False,
        "Manual install + licence (API-driven)",
        False,
    ),
)

#: The number of scanner integrations AEGIS ships (all present in REGISTRY).
SCANNER_COUNT = 24


def by_name(name: str) -> ScannerSpec | None:
    """Return the spec for ``name``, or ``None`` if unknown."""
    for spec in REGISTRY:
        if spec.name == name:
            return spec
    return None


def names() -> list[str]:
    """Return every scanner name, sorted."""
    return sorted(spec.name for spec in REGISTRY)
