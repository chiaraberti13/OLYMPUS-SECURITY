"""Safe Olympus-native guided lab catalog."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class Lab:
    lab_id: str
    title: str
    level: Literal["foundation", "beginner", "intermediate", "advanced"]
    objective: str
    commands: tuple[str, ...]
    evidence: tuple[str, ...]


LABS: tuple[Lab, ...] = (
    Lab(
        "cti-indicator-case",
        "Build a sourced CTI indicator case",
        "beginner",
        "Extract normalized IOCs from a local evidence file and write a confidence-scored report.",
        ("olympus metis case create", "olympus metis case ingest", "olympus metis case report"),
        ("private SQLite case", "versioned JSON or Markdown report"),
    ),
    Lab(
        "passive-recon-pipeline",
        "Model a passive recon event pipeline",
        "beginner",
        "Normalize and correlate local URL, domain, email, IP and username seeds "
        "without network traffic.",
        ("olympus argus pipeline --preset examples/input/argus-pipeline.json",),
        ("versioned event graph", "bounded audit trail"),
    ),
    Lab(
        "detection-rule-lifecycle",
        "Detection rule lifecycle",
        "intermediate",
        "Validate and exercise a versioned MITRE-mapped rule against fixture events.",
        ("olympus apollo rules", "olympus apollo test", "olympus apollo run"),
        ("validated rule", "traceable alert JSON"),
    ),
    Lab(
        "incident-evidence-custody",
        "Incident evidence and custody",
        "intermediate",
        "Triage an alert, preserve evidence digests and verify the custody chain.",
        ("olympus minerva triage", "olympus minerva record", "olympus minerva verify"),
        ("incident record", "verified custody chain"),
    ),
    Lab(
        "authorized-local-web-assessment",
        "Authorized local web assessment",
        "advanced",
        "Run scoped native checks only against the bundled local Mars practice target.",
        ("docker compose -f labs/mars/docker-compose.yml up", "olympus themis run nmap"),
        ("scope contract", "real execution result", "normalized findings"),
    ),
)
