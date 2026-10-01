"""Parser tests for the ProjectDiscovery-family adapters and dalfox.

Every fixture below is **real captured output**, produced by running the actual
binary against a local authorized lab (a Python ``http.server`` on
``127.0.0.1:8099``, plus a deliberately broken one on ``127.0.0.1:8098``). No
public or third-party system was contacted. Long records are trimmed, never
invented; see ``docs/themis-execution-evidence.md``.
"""

from __future__ import annotations

import pytest

from olympus.core.enums import Severity
from olympus.themis.adapters import nuclei as nuclei_module
from olympus.themis.adapters.dalfox import DalfoxAdapter
from olympus.themis.adapters.httpx import HttpxAdapter
from olympus.themis.adapters.katana import KatanaAdapter
from olympus.themis.adapters.nuclei import NucleiAdapter
from olympus.themis.base import ParseError
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput

# --- real captured fixtures (trimmed) -------------------------------------- #

# httpx -target 127.0.0.1:8099 -json -silent -title -web-server -tech-detect
HTTPX_OK = (
    '{"timestamp":"2026-09-05T08:21:35.99365072Z","port":"8099",'
    '"url":"http://127.0.0.1:8099","input":"127.0.0.1:8099",'
    '"title":"Olympus lab target","scheme":"http",'
    '"webserver":"SimpleHTTP/0.6 Python/3.11.15","content_type":"text/html",'
    '"method":"GET","host":"127.0.0.1","host_ip":"127.0.0.1","path":"/",'
    '"a":["127.0.0.1"],"tech":["Python:3.11.15","SimpleHTTP:0.6"],'
    '"status_code":200,"content_length":75,"failed":false}\n'
)
# Same command against a lab server that always answers 500.
HTTPX_SERVER_ERROR = (
    '{"timestamp":"2026-09-05T08:24:46.29400713Z","port":"8098",'
    '"url":"http://127.0.0.1:8098","input":"127.0.0.1:8098","title":"boom",'
    '"scheme":"http","webserver":"BaseHTTP/0.6 Python/3.11.15 LabBroken/1.0",'
    '"method":"GET","host":"127.0.0.1","tech":["Python:3.11.15"],'
    '"status_code":500,"content_length":61,"failed":false}\n'
)
# The Python `httpx` HTTP-client library ships a console script of the same name.
HTTPX_WRONG_TOOL = "Usage: httpx [OPTIONS] URL\n\nError: No such option '--version'.\n"

# katana -u http://127.0.0.1:8099 -jsonl -silent -d 2 -omit-raw -omit-body
KATANA_JSONL = (
    '{"timestamp":"2026-09-05T08:25:17.044842909Z",'
    '"request":{"method":"GET","endpoint":"http://127.0.0.1:8099"},'
    '"response":{"status_code":200,"content_length":64}}\n'
    '{"timestamp":"2026-09-05T08:25:18.046153098Z",'
    '"request":{"method":"GET","endpoint":"http://127.0.0.1:8099/admin/panel",'
    '"tag":"a","attribute":"href","source":"http://127.0.0.1:8099"},'
    '"response":{"status_code":200,"content_length":19}}\n'
    '{"timestamp":"2026-09-05T08:25:18.046305669Z",'
    '"request":{"method":"GET","endpoint":"http://127.0.0.1:8099/about.html",'
    '"tag":"a","attribute":"href","source":"http://127.0.0.1:8099"},'
    '"response":{"status_code":404,"content_length":335}}\n'
)

# nuclei -target http://127.0.0.1:8099 -t <lab template> -jsonl -silent
# -omit-raw -omit-template
NUCLEI_JSONL = (
    '{"template-id":"lab-python-simplehttp",'
    '"info":{"name":"Python SimpleHTTP server exposed","author":["olympus-lab"],'
    '"tags":["tech","http","lab"],'
    '"description":"The lab target discloses a Python SimpleHTTP server banner.",'
    '"severity":"low"},"type":"http","host":"127.0.0.1","port":"8099",'
    '"scheme":"http","url":"http://127.0.0.1:8099",'
    '"matched-at":"http://127.0.0.1:8099/","ip":"127.0.0.1",'
    '"timestamp":"2026-09-05T08:29:39.825637806Z","matcher-status":true}\n'
)
# nuclei on a target where nothing matched: exit 0, nothing on stdout.
NUCLEI_CLEAN = ""

# dalfox url "http://127.0.0.1:8099/?q=1" --format json --silence
# A clean target yields a one-element array holding an EMPTY object.
DALFOX_CLEAN = "[\n{}]"


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


# --- httpx ------------------------------------------------------------------ #


def test_httpx_parser_reports_reachability_server_and_tech() -> None:
    findings = HttpxAdapter().parse(_out(HTTPX_OK), "127.0.0.1", _req())
    titles = [f.title for f in findings]
    assert any("HTTP service reachable (200)" in t for t in titles)
    assert any("Web server disclosed: SimpleHTTP/0.6 Python/3.11.15" in t for t in titles)
    assert any("Technology disclosed: Python:3.11.15" in t for t in titles)
    assert any("Technology disclosed: SimpleHTTP:0.6" in t for t in titles)
    assert all(f.severity == Severity.INFO for f in findings)


def test_httpx_parser_raises_severity_for_a_server_error() -> None:
    findings = HttpxAdapter().parse(_out(HTTPX_SERVER_ERROR), "127.0.0.1", _req())
    reachability = next(f for f in findings if "server error" in f.title)
    assert reachability.severity == Severity.LOW
    assert "500" in reachability.title


def test_httpx_parser_skips_a_failed_probe() -> None:
    failed = '{"url":"http://127.0.0.1:8097","input":"127.0.0.1:8097","failed":true}\n'
    assert HttpxAdapter().parse(_out(failed), "127.0.0.1", _req()) == []


def test_httpx_parser_names_the_binary_collision() -> None:
    """A wrong tool on PATH must never be reported as a clean scan."""
    with pytest.raises(ParseError, match="Python HTTP client library"):
        HttpxAdapter().parse(_out(HTTPX_WRONG_TOOL), "127.0.0.1", _req())


def test_httpx_argv_asks_for_machine_readable_output() -> None:
    argv = HttpxAdapter().build_argv("127.0.0.1", _req())
    assert "-json" in argv and "-silent" in argv


# --- katana ----------------------------------------------------------------- #


def test_katana_parser_lists_discovered_endpoints() -> None:
    findings = KatanaAdapter().parse(_out(KATANA_JSONL), "127.0.0.1", _req())
    assert len(findings) == 3
    assert any("about.html" in f.title for f in findings)


def test_katana_parser_elevates_a_reachable_sensitive_path() -> None:
    findings = KatanaAdapter().parse(_out(KATANA_JSONL), "127.0.0.1", _req())
    admin = next(f for f in findings if "/admin/panel" in f.title)
    assert admin.severity == Severity.MEDIUM
    assert "Sensitive endpoint reachable" in admin.title
    # A 404 on a sensitive-looking path proves nothing and stays INFO.
    missing = next(f for f in findings if "about.html" in f.title)
    assert missing.severity == Severity.INFO


def test_katana_parser_does_not_elevate_an_unreachable_sensitive_path() -> None:
    line = (
        '{"request":{"method":"GET","endpoint":"http://127.0.0.1:8099/admin/secret"},'
        '"response":{"status_code":404}}\n'
    )
    finding = KatanaAdapter().parse(_out(line), "127.0.0.1", _req())[0]
    assert finding.severity == Severity.INFO


def test_katana_parser_rejects_output_that_carries_no_crawl_record() -> None:
    with pytest.raises(ParseError, match="no crawl record"):
        KatanaAdapter().parse(_out("katana: command not found\n"), "127.0.0.1", _req())


def test_katana_argv_keeps_bodies_out_of_evidence() -> None:
    """Response bodies carry cookies and PII; never collect them at all."""
    argv = KatanaAdapter().build_argv("127.0.0.1", _req())
    assert "-omit-raw" in argv and "-omit-body" in argv


# --- nuclei ----------------------------------------------------------------- #


def test_nuclei_parser_maps_template_severity() -> None:
    findings = NucleiAdapter().parse(_out(NUCLEI_JSONL), "127.0.0.1", _req())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.LOW
    assert "lab-python-simplehttp" in finding.title
    assert "matched-at=http://127.0.0.1:8099/" in finding.evidence
    assert "tags=tech,http,lab" in finding.evidence


def test_nuclei_parser_treats_silence_as_a_clean_result() -> None:
    """nuclei exits 0 either way, so an empty stream is a real "nothing found"."""
    assert NucleiAdapter().parse(_out(NUCLEI_CLEAN), "127.0.0.1", _req()) == []


def test_nuclei_parser_never_trusts_an_unknown_severity() -> None:
    line = (
        '{"template-id":"t","info":{"name":"n","severity":"apocalyptic"},'
        '"matched-at":"http://127.0.0.1:8099/"}\n'
    )
    assert NucleiAdapter().parse(_out(line), "127.0.0.1", _req())[0].severity == Severity.INFO


def test_nuclei_parser_rejects_non_jsonl_output() -> None:
    with pytest.raises(ParseError, match="no JSONL object"):
        NucleiAdapter().parse(
            _out("[FTL] Could not run nuclei: no templates provided\n"), "127.0.0.1", _req()
        )


def test_nuclei_argv_keeps_raw_pairs_out_of_evidence() -> None:
    argv = NucleiAdapter().build_argv("127.0.0.1", _req())
    assert "-omit-raw" in argv
    # The same flag must not be passed twice under its long and short spelling.
    assert argv.count("-disable-update-check") == 1
    assert "-duc" not in argv


# --- dalfox ----------------------------------------------------------------- #


def test_dalfox_parser_treats_the_empty_object_array_as_clean() -> None:
    """dalfox emits ``[{}]``, not ``[]``, when it finds nothing."""
    assert DalfoxAdapter().parse(_out(DALFOX_CLEAN), "127.0.0.1", _req()) == []


def test_dalfox_parser_reports_a_verified_proof_of_concept() -> None:
    entry = (
        '[{"type":"V","inject_type":"inHTML-URL","method":"GET","param":"q",'
        '"payload":"<script>alert(45)</script>","cwe":"CWE-79","severity":"high"}]'
    )
    finding = DalfoxAdapter().parse(_out(entry), "127.0.0.1", _req())[0]
    assert finding.severity == Severity.HIGH
    assert finding.title == "Verified XSS in parameter q"
    assert "cwe=CWE-79" in finding.evidence


def test_dalfox_parser_caps_an_unverified_reflection() -> None:
    """Reflection without a verified PoC is a lead, so it cannot claim HIGH."""
    entry = (
        '[{"type":"R","inject_type":"inHTML-URL","method":"GET","param":"q",'
        '"payload":"olympus-probe","severity":"high"}]'
    )
    finding = DalfoxAdapter().parse(_out(entry), "127.0.0.1", _req())[0]
    assert finding.severity == Severity.LOW
    assert "unverified" in finding.title


def test_dalfox_parser_truncates_a_reflected_payload() -> None:
    """The payload is attacker-controlled input; keep it bounded and in evidence."""
    entry = '[{"type":"V","param":"q","payload":"%s"}]' % ("A" * 5_000)
    finding = DalfoxAdapter().parse(_out(entry), "127.0.0.1", _req())[0]
    payload = next(item for item in finding.evidence if item.startswith("payload="))
    assert len(payload) <= len("payload=") + 300
    assert "A" * 5_000 not in finding.title


def test_dalfox_parser_rejects_output_without_a_json_array() -> None:
    with pytest.raises(ParseError, match="no JSON array"):
        DalfoxAdapter().parse(_out("dalfox: fatal\n"), "127.0.0.1", _req())


def test_nuclei_argv_omits_templates_when_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(nuclei_module.TEMPLATES_VARIABLE, raising=False)
    argv = NucleiAdapter().build_argv("127.0.0.1", _req())
    assert "-templates" not in argv


def test_nuclei_argv_passes_the_configured_template_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The sandbox user's $HOME is not the operator's, so be explicit."""
    monkeypatch.setenv(nuclei_module.TEMPLATES_VARIABLE, "/opt/nuclei-templates")
    argv = NucleiAdapter().build_argv("127.0.0.1", _req())
    assert argv[argv.index("-templates") + 1] == "/opt/nuclei-templates"


def test_nuclei_argv_disables_out_of_band_callbacks() -> None:
    """interactsh sends callbacks to a third-party server; never opt in silently."""
    assert "-no-interactsh" in NucleiAdapter().build_argv("127.0.0.1", _req())


def test_nuclei_explains_a_missing_template_directory() -> None:
    failure = _out(stderr="[FTL] Could not run nuclei: no templates provided for scan\n")
    hint = NucleiAdapter().missing_templates_hint(failure)
    assert hint is not None and nuclei_module.TEMPLATES_VARIABLE in hint


def test_nuclei_gives_no_template_hint_for_an_unrelated_failure() -> None:
    assert NucleiAdapter().missing_templates_hint(_out(stderr="connection refused")) is None
