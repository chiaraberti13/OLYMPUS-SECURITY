"""Operator-facing activity and risk classification for THEMIS scanners.

ROADMAP ``WEB-E`` asks for a *guided* New Assessment flow: pick an engagement,
a target and a kind of activity (recon / network / web / vulnerability /
secret / detection / full), then preview — in plain language and with an
explicit ``PASSIVE``/``ACTIVE``/``INTRUSIVE`` risk level — exactly what Olympus
is about to run before any authorization is asked for.

This module is the single, interface-agnostic source of that classification so
the guided flow carries no cybersecurity logic of its own (the web UI, and any
future CLI/TUI wizard, all read the same answers here):

* the **activity type** of a scanner is derived from its registry ``category``
  (:mod:`olympus.integrations.scanners`), never from a hand-maintained list in
  a template, so it cannot drift from the real catalogue;
* the **risk class** has no registry field, so it is an explicit, reviewed map
  with a deliberately *unsafe-to-understate* default: an unmapped scanner is
  treated as :data:`RiskClass.ACTIVE`, never ``PASSIVE``;
* every record also carries a short, non-technical summary for operators who do
  not remember the CLI flags.

Nothing here runs a scanner, reads the environment or contacts a target; it only
classifies the static catalogue.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from olympus.integrations.scanners import REGISTRY, ScannerSpec, by_name


class RiskClass(StrEnum):
    """How intrusive one scanner is against a target, worst-case.

    The ordering is meaningful: ``PASSIVE < ACTIVE < INTRUSIVE``. It drives how
    much friction the guided flow puts in front of a launch.
    """

    PASSIVE = "passive"
    ACTIVE = "active"
    INTRUSIVE = "intrusive"


class ActivityType(StrEnum):
    """The kind of assessment an operator chooses in the guided flow."""

    RECON = "recon"
    NETWORK = "network"
    WEB = "web"
    VULNERABILITY = "vulnerability"
    SECRET = "secret"  # noqa: S105 - an activity name, not a credential
    DETECTION = "detection"
    FULL = "full"


#: Plain-language explanation of each risk class, shown in the preview so the
#: operator understands the consequence before authorizing.
RISK_EXPLANATION: dict[RiskClass, str] = {
    RiskClass.PASSIVE: (
        "Observes public information and sends little or no traffic to the target. Lowest impact."
    ),
    RiskClass.ACTIVE: (
        "Sends requests directly to the target to enumerate and probe it. "
        "Non-destructive, but clearly visible to the target."
    ),
    RiskClass.INTRUSIVE: (
        "Attempts injection or exploitation techniques against the target. "
        "Only run this with explicit, written authorization."
    ),
}


#: Scanner category (from the registry) → the activity an operator would pick.
#: Categories are fixed in :mod:`olympus.integrations.scanners`; an unexpected
#: one falls back to :data:`ActivityType.WEB` (the broadest bucket) rather than
#: being dropped silently.
_CATEGORY_ACTIVITY: dict[str, ActivityType] = {
    "network": ActivityType.NETWORK,
    "tls": ActivityType.NETWORK,
    "dns": ActivityType.RECON,
    "web": ActivityType.WEB,
    "vuln": ActivityType.VULNERABILITY,
}


#: Explicit, reviewed risk class per scanner. Anything missing defaults to
#: :data:`RiskClass.ACTIVE` in :func:`_risk_for` — understating risk is never
#: the safe failure mode, so ``PASSIVE`` is only ever assigned deliberately.
_RISK_CLASS: dict[str, RiskClass] = {
    # Passive OSINT / public-record collection.
    "subfinder": RiskClass.PASSIVE,
    "theharvester": RiskClass.PASSIVE,
    # Active, non-destructive enumeration and probing.
    "nmap": RiskClass.ACTIVE,
    "testssl": RiskClass.ACTIVE,
    "whatweb": RiskClass.ACTIVE,
    "httpx": RiskClass.ACTIVE,
    "wafw00f": RiskClass.ACTIVE,
    "katana": RiskClass.ACTIVE,
    "nikto": RiskClass.ACTIVE,
    "nuclei": RiskClass.ACTIVE,
    "dirsearch": RiskClass.ACTIVE,
    "arjun": RiskClass.ACTIVE,
    "wpscan": RiskClass.ACTIVE,
    "wapiti": RiskClass.ACTIVE,
    "zap": RiskClass.ACTIVE,
    "openvas": RiskClass.ACTIVE,
    "nessus": RiskClass.ACTIVE,
    "acunetix": RiskClass.ACTIVE,
    "burp": RiskClass.ACTIVE,
    # Intrusive: active injection / exploitation attempts.
    "sqlmap": RiskClass.INTRUSIVE,
    "commix": RiskClass.INTRUSIVE,
    "xsstrike": RiskClass.INTRUSIVE,
    "dalfox": RiskClass.INTRUSIVE,
    "nosqlmap": RiskClass.INTRUSIVE,
}


#: Short, non-technical summaries for the scanners an operator meets most often.
#: Anything without an entry falls back to the registry ``purpose`` string, so a
#: new scanner is still described honestly rather than left blank.
_PLAIN_SUMMARY: dict[str, str] = {
    "nmap": "Finds which network ports and services a host exposes.",
    "testssl": "Checks how a server's TLS/SSL encryption is configured.",
    "subfinder": "Discovers subdomains of a domain from public sources.",
    "theharvester": "Collects public emails and subdomains for a domain (OSINT).",
    "httpx": "Probes web servers to see which respond and how.",
    "whatweb": "Identifies the technologies a website is built with.",
    "wafw00f": "Detects whether a web application firewall is in front of a site.",
    "katana": "Crawls a website to map its pages and endpoints.",
    "nikto": "Scans a web server for common misconfigurations.",
    "nuclei": "Checks a target against a large library of known-vulnerability templates.",
    "dirsearch": "Looks for hidden files and directories on a web server.",
    "arjun": "Discovers hidden HTTP parameters a web page accepts.",
    "wpscan": "Checks a WordPress site for known vulnerable plugins and themes.",
    "wapiti": "Scans a web application for common vulnerabilities.",
    "zap": "Runs the OWASP ZAP dynamic web-application scanner (service).",
    "openvas": "Runs the OpenVAS/GVM network vulnerability scanner (service).",
    "nessus": "Runs a Tenable Nessus vulnerability scan (licensed service).",
    "acunetix": "Runs an Invicti/Acunetix web vulnerability scan (licensed service).",
    "burp": "Drives a PortSwigger Burp Suite scan (licensed service).",
    "sqlmap": "Actively tests a site for SQL-injection weaknesses.",
    "commix": "Actively tests a site for command-injection weaknesses.",
    "xsstrike": "Actively tests a site for cross-site-scripting (XSS) weaknesses.",
    "dalfox": "Actively tests a site for cross-site-scripting (XSS) weaknesses.",
    "nosqlmap": "Actively tests a site for NoSQL-injection weaknesses.",
}


@dataclass(frozen=True)
class ActivityInfo:
    """Operator-facing description of one activity type."""

    activity: ActivityType
    title: str
    summary: str
    #: True when this activity runs as a THEMIS scanner job through the web
    #: control plane; False when it lives in another Olympus module and is only
    #: honestly surfaced (with a CLI hint) rather than faked here.
    themis_native: bool
    #: For non-native activities, how to run it today.
    cli_hint: str | None = None


#: Every activity the guided flow offers, in presentation order. Recon through
#: vulnerability run as THEMIS scanner jobs; secret, detection and full are
#: honestly marked as living in other modules so the flow never pretends the
#: web control plane can run them yet.
ACTIVITY_CATALOGUE: tuple[ActivityInfo, ...] = (
    ActivityInfo(
        ActivityType.RECON,
        "Reconnaissance",
        "Map the target's public footprint: subdomains, hosts and exposed services.",
        themis_native=True,
    ),
    ActivityInfo(
        ActivityType.NETWORK,
        "Network",
        "Enumerate open ports, services and transport-layer (TLS) configuration.",
        themis_native=True,
    ),
    ActivityInfo(
        ActivityType.WEB,
        "Web application",
        "Probe a website or web application for misconfigurations and weaknesses.",
        themis_native=True,
    ),
    ActivityInfo(
        ActivityType.VULNERABILITY,
        "Vulnerability assessment",
        "Run a dedicated vulnerability scanner against the target.",
        themis_native=True,
    ),
    ActivityInfo(
        ActivityType.SECRET,
        "Secret scan",
        "Search source or filesystems for leaked credentials and secrets.",
        themis_native=False,
        cli_hint="olympus hermes scan",
    ),
    ActivityInfo(
        ActivityType.DETECTION,
        "Detection engineering",
        "Validate detection rules against ingested telemetry.",
        themis_native=False,
        cli_hint="olympus apollo run",
    ),
    ActivityInfo(
        ActivityType.FULL,
        "Full assessment",
        "Chain recon → scan → enrich → report in one orchestrated playbook.",
        themis_native=False,
        cli_hint="olympus athena run",
    ),
)

_ACTIVITY_INFO: dict[ActivityType, ActivityInfo] = {
    info.activity: info for info in ACTIVITY_CATALOGUE
}

#: Preferred scanner for each native activity's *automatic* mode, in order of
#: preference. The first one that is ``ready`` on the host is chosen; if none is
#: ready, the guided flow says so honestly rather than queueing nothing.
_RECOMMENDED: dict[ActivityType, tuple[str, ...]] = {
    ActivityType.RECON: ("subfinder", "httpx", "whatweb", "theharvester", "katana", "wafw00f"),
    ActivityType.NETWORK: ("nmap", "testssl"),
    ActivityType.WEB: ("nuclei", "nikto", "dirsearch", "wpscan", "zap"),
    ActivityType.VULNERABILITY: ("openvas", "nessus", "nuclei"),
}


def _risk_for(name: str) -> RiskClass:
    """Return the reviewed risk class, defaulting to ACTIVE when unmapped."""
    return _RISK_CLASS.get(name, RiskClass.ACTIVE)


def _activity_for(spec: ScannerSpec) -> ActivityType:
    """Return the activity bucket for a scanner, derived from its category."""
    return _CATEGORY_ACTIVITY.get(spec.category, ActivityType.WEB)


@dataclass(frozen=True)
class ScannerActivity:
    """How one scanner is presented in the guided flow."""

    name: str
    activity: ActivityType
    risk: RiskClass
    summary: str

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "activity": self.activity.value,
            "risk": self.risk.value,
            "risk_explanation": RISK_EXPLANATION[self.risk],
            "summary": self.summary,
        }


def classify(spec: ScannerSpec) -> ScannerActivity:
    """Classify one scanner spec into its activity, risk and plain summary."""
    return ScannerActivity(
        name=spec.name,
        activity=_activity_for(spec),
        risk=_risk_for(spec.name),
        summary=_PLAIN_SUMMARY.get(spec.name, spec.purpose),
    )


def profile(name: str) -> ScannerActivity | None:
    """Return the activity profile for ``name`` or ``None`` if unknown."""
    spec = by_name(name)
    return classify(spec) if spec is not None else None


def profiles() -> list[ScannerActivity]:
    """Return every scanner's activity profile, sorted by name."""
    return [classify(spec) for spec in sorted(REGISTRY, key=lambda item: item.name)]


def activity_info(activity: ActivityType) -> ActivityInfo:
    """Return the operator-facing description of one activity type."""
    return _ACTIVITY_INFO[activity]


def scanners_for_activity(activity: ActivityType) -> list[ScannerActivity]:
    """Return every scanner mapped to ``activity``, sorted by risk then name."""
    matching = [item for item in profiles() if item.activity is activity]
    order = {RiskClass.PASSIVE: 0, RiskClass.ACTIVE: 1, RiskClass.INTRUSIVE: 2}
    return sorted(matching, key=lambda item: (order[item.risk], item.name))


def recommended_scanner(activity: ActivityType, ready: set[str]) -> str | None:
    """Return the automatic-mode scanner for ``activity`` given ``ready`` names.

    The first preferred scanner that is ready on this host wins; when none of
    the preferred ones are ready, any other ready scanner in the activity is
    used; when the activity has no ready scanner at all, ``None`` is returned so
    the caller can refuse honestly instead of pretending something will run.
    """
    for candidate in _RECOMMENDED.get(activity, ()):  # preferred order first
        if candidate in ready and profile(candidate) is not None:
            spec = by_name(candidate)
            if spec is not None and _activity_for(spec) is activity:
                return candidate
    for item in scanners_for_activity(activity):  # any ready scanner otherwise
        if item.name in ready:
            return item.name
    return None
