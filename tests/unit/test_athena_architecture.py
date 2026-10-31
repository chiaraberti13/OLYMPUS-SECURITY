"""Guard the accepted Athena target architecture against accidental omissions."""

from pathlib import Path

ADR = Path("docs/architecture/adr-002-athena-target-architecture.md")


def test_target_architecture_records_required_decisions() -> None:
    document = ADR.read_text(encoding="utf-8")
    required_sections = {
        "## Package boundaries and dependency direction",
        "## Domain contracts",
        "## Ports and adapter contract",
        "## Execution model",
        "## Persistence and recovery",
        "## Authorization, audit, and sensitive data",
        "## CLI, API, and UI surfaces",
        "## Migration strategy",
        "## Delivery slices and acceptance",
    }

    assert "- **Status:** Accepted" in document
    assert required_sections <= set(document.splitlines())


def test_target_architecture_is_non_binding() -> None:
    # The ADR must not act as a development constraint: it declares itself a
    # non-binding guideline that never blocks features.
    document = ADR.read_text(encoding="utf-8")
    assert "non-binding" in document.lower()


def test_target_architecture_keeps_security_invariants_explicit() -> None:
    # Only genuine SECURITY invariants remain mandatory; non-security
    # architectural restrictions were intentionally relaxed.
    document = ADR.read_text(encoding="utf-8")

    for invariant in (
        "Unknown adapters are rejected",
        "owner-only permissions",
        "`..` traversal are rejected",
        "raw discovered secrets are never persisted",
    ):
        assert invariant in document
