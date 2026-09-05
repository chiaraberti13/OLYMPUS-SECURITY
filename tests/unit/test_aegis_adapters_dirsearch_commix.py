"""Parser tests for the dirsearch and commix adapters.

Every fixture is **real captured output**, produced by running the actual tool
through ``olympus aegis run`` against a local authorized lab: a Python
``http.server`` on ``127.0.0.1:8099`` for content discovery, and a deliberately
command-injectable CGI-style server on ``127.0.0.1:8094`` for commix. No public
or third-party system was contacted. See ``docs/aegis-execution-evidence.md``.
"""

from __future__ import annotations

import pytest

from olympus.aegis.adapters.commix import CommixAdapter
from olympus.aegis.adapters.dirsearch import DirsearchAdapter
from olympus.aegis.base import ParseError
from olympus.aegis.model import ScanRequest
from olympus.aegis.runner import CommandOutput
from olympus.core.enums import Severity

# --- real captured fixtures ------------------------------------------------ #

# dirsearch -u http://127.0.0.1:8099/ -q --no-color (result stream on stdout)
DIRSEARCH_STDOUT = (
    "[21:19:12] 301 -     0B - http://127.0.0.1:8099/admin  ->  /admin/\n"
    "[21:19:12] 200 -   234B - http://127.0.0.1:8099/admin/\n"
    "[21:19:19] 200 -    64B - http://127.0.0.1:8099/index.html\n"
    "[21:19:23] 301 -     0B - http://127.0.0.1:8099/private  ->  /private/\n"
)
# A reachable secret file, captured from a lab that serves /private/.env.
DIRSEARCH_ENV_FILE = "[09:50:25] 200 -     7B - http://127.0.0.1:8099/private/.env\n"

# commix -u '.../?addr=127.0.0.1' --batch --ignore-session (info lines on stdout)
COMMIX_STDOUT = (
    "[21:16:14] [info] Identified a potential injection point on GET parameter 'addr'.\n"
    "[21:16:14] [info] GET parameter 'addr' appears to be injectable via classic "
    "results-based technique.\n"
    "[21:16:29] [info] GET parameter 'addr' appears to be injectable via time-based "
    "blind technique.\n"
    "[21:16:49] [info] GET parameter 'addr' appears to be injectable via file-based "
    "semi-blind technique.\n"
)
# A clean parameter: commix states it is not injectable and gives up.
COMMIX_CLEAN = (
    "[21:16:51] [warning] Heuristic (basic) test shows that GET parameter 'addr' "
    "might not be injectable.\n"
    "[21:16:52] [warning] GET parameter 'addr' does not seem to be injectable.\n"
    "[21:16:52] [critical] All tested parameters do not appear to be injectable.\n"
)


def _out(stdout: str = "", stderr: str = "", code: int = 0) -> CommandOutput:
    return CommandOutput(exit_code=code, stdout=stdout, stderr=stderr)


def _req(**kw: object) -> ScanRequest:
    base: dict[str, object] = {
        "scanner": "x",
        "target": "127.0.0.1",
        "allowed": ("127.0.0.1",),
    }
    base.update(kw)
    return ScanRequest(**base)  # type: ignore[arg-type]


# --- dirsearch -------------------------------------------------------------- #


def test_dirsearch_parser_lists_discovered_paths() -> None:
    findings = DirsearchAdapter().parse(_out(DIRSEARCH_STDOUT), "127.0.0.1", _req())
    assert len(findings) == 4
    index = next(f for f in findings if "index.html" in f.title)
    assert index.severity == Severity.INFO
    assert "status=200" in index.evidence


def test_dirsearch_parser_elevates_a_sensitive_reachable_path() -> None:
    findings = DirsearchAdapter().parse(_out(DIRSEARCH_STDOUT), "127.0.0.1", _req())
    admin = next(f for f in findings if f.title.endswith("/admin"))
    assert admin.severity == Severity.MEDIUM
    assert "Sensitive path reachable" in admin.title
    assert "redirect=/admin/" in admin.evidence


def test_dirsearch_parser_flags_a_reachable_secret_file() -> None:
    finding = DirsearchAdapter().parse(_out(DIRSEARCH_ENV_FILE), "127.0.0.1", _req())[0]
    assert finding.severity == Severity.MEDIUM
    assert ".env" in finding.title


def test_dirsearch_parser_reports_a_forbidden_path_as_low() -> None:
    """A 403 still proves the resource exists — a weaker signal, not none."""
    line = "[09:50:25] 403 -   12B - http://127.0.0.1:8099/backup\n"
    finding = DirsearchAdapter().parse(_out(line), "127.0.0.1", _req())[0]
    assert finding.severity == Severity.LOW
    assert "forbidden (403)" in finding.title


def test_dirsearch_parser_treats_a_quiet_run_as_clean() -> None:
    assert DirsearchAdapter().parse(_out(""), "127.0.0.1", _req()) == []


def test_dirsearch_parser_rejects_output_without_a_result_line() -> None:
    with pytest.raises(ParseError, match="no result line"):
        DirsearchAdapter().parse(
            _out("dirsearch: ModuleNotFoundError: No module named 'requests'\n"),
            "127.0.0.1",
            _req(),
        )


def test_dirsearch_argv_is_quiet_and_uncolored() -> None:
    argv = DirsearchAdapter().build_argv("127.0.0.1", _req(target="http://127.0.0.1/"))
    assert "-q" in argv and "--no-color" in argv


# --- commix ----------------------------------------------------------------- #


def test_commix_parser_reports_one_critical_per_technique() -> None:
    findings = CommixAdapter().parse(_out(COMMIX_STDOUT), "127.0.0.1", _req())
    assert len(findings) == 3
    assert all(f.severity == Severity.CRITICAL for f in findings)
    techniques = {
        item.split("=", 1)[1]
        for f in findings
        for item in f.evidence
        if item.startswith("technique=")
    }
    assert techniques == {"classic results-based", "time-based blind", "file-based semi-blind"}


def test_commix_parser_deduplicates_a_repeated_line() -> None:
    doubled = COMMIX_STDOUT + COMMIX_STDOUT
    assert len(CommixAdapter().parse(_out(doubled), "127.0.0.1", _req())) == 3


def test_commix_parser_treats_a_clean_parameter_as_no_findings() -> None:
    assert CommixAdapter().parse(_out(COMMIX_CLEAN), "127.0.0.1", _req()) == []


def test_commix_parser_never_ships_the_exploit_payload() -> None:
    """The finding stands on its own; a working injection string is not evidence."""
    finding = CommixAdapter().parse(_out(COMMIX_STDOUT), "127.0.0.1", _req())[0]
    joined = " ".join(finding.evidence)
    assert "echo" not in joined and ";" not in joined and "sleep" not in joined


def test_commix_argv_is_non_interactive_and_sessionless() -> None:
    """Interactive by default would block forever under the sandbox."""
    argv = CommixAdapter().build_argv("127.0.0.1", _req(target="http://127.0.0.1/?x=1"))
    assert "--batch" in argv and "--ignore-session" in argv
