"""Parser tests for the arjun adapter.

Fixtures are real captured output, produced by running arjun through
``olympus aegis run`` against a local authorized lab: a server on
``127.0.0.1:8092`` that honours the hidden parameters ``id`` and ``debug``, and
one on ``127.0.0.1:8091`` that honours none. See
``docs/aegis-execution-evidence.md``.
"""

from __future__ import annotations

from olympus.aegis.adapters.arjun import ArjunAdapter
from olympus.aegis.model import ScanRequest
from olympus.aegis.runner import CommandOutput
from olympus.core.enums import Severity

# Real stdout through Olympus (NO_COLOR=1, so no ANSI); progress lines omitted.
ARJUN_STDOUT = (
    "[✓] parameter detected: debug, based on: body length\n"
    "[✓] parameter detected: id, based on: body length\n"
    "[+] Parameters found: debug, id\n"
)
# The same tool run coloured on a TTY, to prove ANSI is tolerated.
ARJUN_COLOURED = (
    "\x1b[1;92m[✓]\x1b[0m parameter detected: token, based on: body length\n"
)


def _out(stdout: str = "", stderr: str = "", code: int = 0) -> CommandOutput:
    return CommandOutput(exit_code=code, stdout=stdout, stderr=stderr)


def _req(**kw: object) -> ScanRequest:
    base: dict[str, object] = {"scanner": "x", "target": "127.0.0.1", "allowed": ("127.0.0.1",)}
    base.update(kw)
    return ScanRequest(**base)  # type: ignore[arg-type]


def test_arjun_parser_reports_each_hidden_parameter() -> None:
    findings = ArjunAdapter().parse(_out(ARJUN_STDOUT), "127.0.0.1", _req())
    names = {item.split("=", 1)[1] for f in findings for item in f.evidence
             if item.startswith("parameter=")}
    assert names == {"debug", "id"}
    assert all(f.severity == Severity.INFO for f in findings)
    assert all("detected_by=body length" in f.evidence for f in findings)


def test_arjun_parser_keeps_the_detection_reason() -> None:
    finding = ArjunAdapter().parse(_out(ARJUN_STDOUT), "127.0.0.1", _req())[0]
    assert "Hidden HTTP parameter:" in finding.title
    assert "body length" in finding.description


def test_arjun_parser_ignores_the_summary_line() -> None:
    """The [+] summary repeats the names; only the per-parameter lines count."""
    only_summary = "[+] Parameters found: debug, id\n"
    assert ArjunAdapter().parse(_out(only_summary), "127.0.0.1", _req()) == []


def test_arjun_parser_tolerates_ansi_colour() -> None:
    finding = ArjunAdapter().parse(_out(ARJUN_COLOURED), "127.0.0.1", _req())[0]
    assert "token" in finding.title


def test_arjun_parser_treats_no_detection_as_clean() -> None:
    noise = "[!] Processing chunks: 1/103\n[!] Processing chunks: 2/103\n"
    assert ArjunAdapter().parse(_out(noise), "127.0.0.1", _req()) == []


def test_arjun_parser_deduplicates_a_repeated_parameter() -> None:
    doubled = ARJUN_STDOUT + "[✓] parameter detected: id, based on: body length\n"
    assert len(ArjunAdapter().parse(_out(doubled), "127.0.0.1", _req())) == 2


def test_arjun_parser_rejects_a_garbled_name() -> None:
    line = "[✓] parameter detected: not a valid name here!!, based on: body length\n"
    assert ArjunAdapter().parse(_out(line), "127.0.0.1", _req()) == []


def test_arjun_argv_bounds_concurrency() -> None:
    argv = ArjunAdapter().build_argv("127.0.0.1", _req(target="http://127.0.0.1/"))
    assert "-t" in argv
