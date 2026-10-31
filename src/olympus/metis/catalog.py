"""Native capability catalog and explainable deterministic router.

The catalog adopts useful ideas from specialist-agent and cybersecurity-skill
collections without importing prompts, runtime code, or external repositories.
Routing is intentionally local and deterministic: no model, API key, or hidden
network request is involved.
"""

from __future__ import annotations

import re
from collections import Counter

from olympus.metis.models import CapabilityProfile, NoiseLevel, OperatingMode, Recommendation


def _capability(
    capability_id: str,
    title: str,
    summary: str,
    *,
    tags: tuple[str, ...],
    phases: tuple[str, ...],
    commands: tuple[str, ...],
    mode: OperatingMode = OperatingMode.ADVISORY,
    noise: NoiseLevel = NoiseLevel.QUIET,
    authorization: bool = False,
    mitre: tuple[str, ...] = (),
) -> CapabilityProfile:
    return CapabilityProfile(
        capability_id=capability_id,
        title=title,
        summary=summary,
        tags=tags,
        phases=phases,
        commands=commands,
        mode=mode,
        noise=noise,
        requires_authorization=authorization,
        mitre_attack=mitre,
    )


CAPABILITIES: tuple[CapabilityProfile, ...] = (
    _capability(
        "engagement-planning",
        "Engagement planning",
        "Build a phased, scope-aware security engagement plan with explicit authorization gates.",
        tags=("plan", "pentest", "scope", "authorization", "methodology", "red-team"),
        phases=("prepare", "scope", "execute", "close"),
        commands=("olympus metis plan", "olympus athena plan validate"),
    ),
    _capability(
        "passive-recon",
        "Passive reconnaissance",
        "Collect and correlate domain, DNS, certificate, WHOIS, web and account intelligence.",
        tags=("osint", "recon", "domain", "dns", "whois", "certificate", "username"),
        phases=("discovery", "enrichment", "correlation"),
        commands=("olympus argus scan", "olympus argus investigate", "olympus argus pipeline"),
        mode=OperatingMode.PASSIVE,
    ),
    _capability(
        "identity-osint",
        "Identity and contact OSINT",
        "Profile authorized usernames, email addresses, phone numbers, IP addresses "
        "and public accounts.",
        tags=("username", "account", "email", "phone", "ip", "identity", "osint"),
        phases=("intake", "normalize", "enrich", "report"),
        commands=(
            "olympus argus accounts",
            "olympus argus email",
            "olympus argus phone",
            "olympus argus ip",
        ),
        mode=OperatingMode.PASSIVE,
        authorization=True,
    ),
    _capability(
        "vulnerability-assessment",
        "Vulnerability assessment",
        "Plan, execute, persist and report bounded vulnerability assessments with "
        "real scanner state.",
        tags=("vulnerability", "scanner", "cve", "cvss", "assessment", "nmap", "nuclei"),
        phases=("scope", "scan", "validate", "prioritize", "report"),
        commands=("olympus athena run", "olympus themis run", "olympus vulcan report"),
        mode=OperatingMode.ACTIVE,
        noise=NoiseLevel.LOUD,
        authorization=True,
    ),
    _capability(
        "web-security",
        "Web and API security assessment",
        "Assess web exposure, content, fingerprinting, headers, XSS and scanner findings in scope.",
        tags=("web", "api", "http", "xss", "owasp", "headers", "content", "sql-injection"),
        phases=("fingerprint", "enumerate", "test", "verify"),
        commands=("olympus artemis fingerprint", "olympus artemis content", "olympus themis run"),
        mode=OperatingMode.ACTIVE,
        noise=NoiseLevel.MODERATE,
        authorization=True,
        mitre=("T1190",),
    ),
    _capability(
        "network-mapping",
        "Network attack-surface mapping",
        "Map authorized hosts and services with bounded timeouts and normalized findings.",
        tags=("network", "ports", "services", "nmap", "attack-surface", "host"),
        phases=("discover", "enumerate", "classify"),
        commands=("olympus helios scan", "olympus themis run nmap"),
        mode=OperatingMode.ACTIVE,
        noise=NoiseLevel.MODERATE,
        authorization=True,
        mitre=("T1046",),
    ),
    _capability(
        "detection-engineering",
        "Detection engineering",
        "Author and test versioned detection rules with MITRE mappings and traceable "
        "alert evidence.",
        tags=("detection", "sigma", "siem", "rule", "mitre", "alert", "blue-team"),
        phases=("hypothesis", "rule", "test", "tune"),
        commands=("olympus apollo rules", "olympus apollo test", "olympus apollo run"),
        mitre=("T1059.001", "T1003.001"),
    ),
    _capability(
        "incident-response",
        "Incident triage and evidence custody",
        "Triage alerts, preserve evidence custody, build timelines and verify incident artifacts.",
        tags=("incident", "forensics", "triage", "timeline", "evidence", "custody", "soc"),
        phases=("identify", "preserve", "triage", "contain", "learn"),
        commands=("olympus minerva triage", "olympus minerva record", "olympus minerva verify"),
    ),
    _capability(
        "threat-intelligence",
        "Cyber threat intelligence casework",
        "Extract indicators, maintain sourced findings, correlate evidence and render "
        "portable case reports.",
        tags=("cti", "threat-intelligence", "ioc", "campaign", "actor", "malware", "correlation"),
        phases=("intake", "extract", "assess", "correlate", "disseminate"),
        commands=(
            "olympus metis case ingest",
            "olympus metis case finding",
            "olympus metis case report",
        ),
    ),
    _capability(
        "secret-scanning",
        "Secret and sensitive-data scanning",
        "Scan local files and Git history with bounded coverage, masking and SARIF output.",
        tags=("secret", "credential", "token", "sarif", "git", "dlp", "supply-chain"),
        phases=("discover", "classify", "remediate", "verify"),
        commands=("olympus hermes scan",),
    ),
    _capability(
        "reporting-risk",
        "Risk scoring and reporting",
        "Aggregate, deduplicate, prioritize and export security findings with retained provenance.",
        tags=("report", "risk", "cvss", "prioritize", "deduplicate", "executive"),
        phases=("aggregate", "rank", "explain", "export"),
        commands=("olympus vulcan rank", "olympus vulcan report"),
    ),
    _capability(
        "social-engineering-simulation",
        "Authorized social-engineering simulation",
        "Prepare bounded training artifacts and campaign metrics without delivering messages.",
        tags=("phishing", "social-engineering", "campaign", "awareness", "email"),
        phases=("authorize", "design", "render", "measure"),
        commands=("olympus proteus campaign", "olympus proteus report"),
        mode=OperatingMode.ACTIVE,
        noise=NoiseLevel.LOUD,
        authorization=True,
        mitre=("T1566",),
    ),
    _capability(
        "security-compliance",
        "Security controls and compliance mapping",
        "Map technical evidence and findings to controls without claiming certification "
        "or legal advice.",
        tags=("compliance", "nist", "iso27001", "cis", "controls", "audit", "grc"),
        phases=("scope", "map", "evidence", "gaps", "remediation"),
        commands=("olympus vulcan report", "olympus metis plan"),
    ),
    _capability(
        "fix-verification",
        "Remediation verification",
        "Re-run bounded checks, compare normalized results and retain evidence of "
        "remediation state.",
        tags=("verify", "remediation", "retest", "diff", "regression", "finding"),
        phases=("baseline", "retest", "compare", "close"),
        commands=("olympus argus diff", "olympus athena run", "olympus vulcan report"),
        mode=OperatingMode.ACTIVE,
        noise=NoiseLevel.MODERATE,
        authorization=True,
    ),
)

_TOKEN = re.compile(r"[a-z0-9][a-z0-9+.#-]*")


def _tokens(value: str) -> Counter[str]:
    return Counter(_TOKEN.findall(value.casefold()))


def recommend(
    task: str,
    *,
    limit: int = 5,
    include_active: bool = True,
) -> tuple[Recommendation, ...]:
    """Return the highest scoring capabilities with transparent term matches."""
    if not task.strip():
        raise ValueError("task must not be empty")
    if not 1 <= limit <= 20:
        raise ValueError("limit must be between 1 and 20")
    task_tokens = _tokens(task)
    ranked: list[Recommendation] = []
    for capability in CAPABILITIES:
        if capability.mode is OperatingMode.ACTIVE and not include_active:
            continue
        weighted: Counter[str] = Counter()
        for tag in capability.tags:
            for token in _tokens(tag):
                weighted[token] += 5
        for phase in capability.phases:
            for token in _tokens(phase):
                weighted[token] += 2
        for token in _tokens(capability.title + " " + capability.summary):
            weighted[token] += 1
        matches = sorted(task_tokens.keys() & weighted.keys())
        score = sum(min(task_tokens[token], 2) * weighted[token] for token in matches)
        if score:
            ranked.append(
                Recommendation(
                    capability=capability,
                    score=score,
                    matched_terms=tuple(matches),
                )
            )
    ranked.sort(key=lambda item: (-item.score, item.capability.capability_id))
    if not ranked:
        fallback = next(
            item for item in CAPABILITIES if item.capability_id == "engagement-planning"
        )
        ranked.append(Recommendation(capability=fallback, score=1, matched_terms=()))
    return tuple(ranked[:limit])
