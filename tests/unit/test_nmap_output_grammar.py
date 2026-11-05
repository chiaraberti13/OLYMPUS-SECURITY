"""nmap adapter output grammar / canonical states (TOOLS-4.4, fail-closed).

These exercise the nmap adapter on outputs that are well-formed XML but are NOT
a clean, completed scan. The XML below follows nmap's real DTD (``<nmaprun>``
with a ``<runstats><finished exit=...>`` trailer and a per-host ``<status>``):
it is what nmap itself emits when a scan fails, does not finish, or the target
host is not up. The real *clean*-output parse lives in
``test_themis_adapters_live_capture.py`` against captured tool output; here the
concern is the opposite path — that an unknown error or an incomplete scan can
never read as a clean target.
"""

from __future__ import annotations

import pytest

from olympus.themis.adapters.nmap import NmapAdapter
from olympus.themis.base import ParseError
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput

_HEAD = '<?xml version="1.0"?>\n<!DOCTYPE nmaprun>\n'


def _out(stdout: str = "", code: int = 0) -> CommandOutput:
    return CommandOutput(exit_code=code, stdout=stdout, stderr="")


def _req() -> ScanRequest:
    return ScanRequest(  # type: ignore[arg-type]
        scanner="nmap", target="127.0.0.1", allowed=("127.0.0.1",)
    )


def _nmaprun(body: str) -> str:
    return f'{_HEAD}<nmaprun scanner="nmap" version="7.94" xmloutputversion="1.05">{body}</nmaprun>'


def test_declared_scan_error_reads_as_failed_not_clean() -> None:
    # nmap can exit 0 yet declare failure in its run trailer: a known error that
    # must surface as a parse failure (FAILED), never as "no open ports".
    xml = _nmaprun(
        '<runstats><finished time="1" exit="error" '
        'errormsg="Failed to resolve &quot;target&quot;"/></runstats>'
    )
    with pytest.raises(ParseError) as exc:
        NmapAdapter().parse(_out(xml), "127.0.0.1", _req())
    assert "failed scan" in str(exc.value)
    assert "Failed to resolve" in str(exc.value)


def test_non_nmap_xml_reads_as_failed_not_clean() -> None:
    # Well-formed XML from the wrong program carries no ports; it must fail closed
    # rather than read as a clean target.
    xml = '<?xml version="1.0"?>\n<html><body>error</body></html>'
    with pytest.raises(ParseError) as exc:
        NmapAdapter().parse(_out(xml), "127.0.0.1", _req())
    assert "not <nmaprun>" in str(exc.value)


def test_a_clean_completed_scan_is_not_partial() -> None:
    # exit=success + host up + one open port => trustworthy; no coverage loss, so
    # a genuine clean/complete scan is never turned into a false partial.
    xml = _nmaprun(
        '<host><status state="up" reason="user-set"/>'
        '<address addr="127.0.0.1" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http"/></port></ports></host>'
        '<runstats><finished time="1" exit="success"/>'
        '<hosts up="1" down="0" total="1"/></runstats>'
    )
    adapter = NmapAdapter()
    findings = adapter.parse(_out(xml), "127.0.0.1", _req())
    assert len(findings) == 1
    assert adapter.coverage_loss(_out(xml), _req()) is None


def test_a_scan_without_a_success_trailer_is_partial_not_clean() -> None:
    # No <finished>: the scan did not complete, so "no open ports" cannot be
    # trusted — the run must read as partial, not clean.
    xml = _nmaprun(
        '<host><status state="up" reason="user-set"/>'
        '<address addr="127.0.0.1" addrtype="ipv4"/><ports></ports></host>'
    )
    adapter = NmapAdapter()
    assert adapter.parse(_out(xml), "127.0.0.1", _req()) == []
    reason = adapter.coverage_loss(_out(xml), _req())
    assert reason is not None
    assert "successful completion" in reason


def test_a_host_that_was_not_up_is_partial_not_clean() -> None:
    # Host down even though the trailer says success: its ports were never
    # scanned, so zero findings must read as partial, not as a clean target.
    xml = _nmaprun(
        '<host><status state="down" reason="no-response"/>'
        '<address addr="127.0.0.1" addrtype="ipv4"/></host>'
        '<runstats><finished time="1" exit="success"/>'
        '<hosts up="0" down="1" total="1"/></runstats>'
    )
    adapter = NmapAdapter()
    assert adapter.parse(_out(xml), "127.0.0.1", _req()) == []
    reason = adapter.coverage_loss(_out(xml), _req())
    assert reason is not None
    assert "host state is down" in reason


def test_no_host_record_is_partial_not_clean() -> None:
    # exit=success but nmap returned no host at all for the single target: the
    # target was not scanned, so the run is partial, never silently clean.
    xml = _nmaprun('<runstats><finished time="1" exit="success"/></runstats>')
    adapter = NmapAdapter()
    assert adapter.parse(_out(xml), "127.0.0.1", _req()) == []
    reason = adapter.coverage_loss(_out(xml), _req())
    assert reason is not None
    assert "no host record" in reason


def test_coverage_reason_resets_between_runs() -> None:
    # The adapter instance may be reused; a partial run must not leave its reason
    # set for a later clean parse on the same instance.
    adapter = NmapAdapter()
    incomplete = _nmaprun(
        '<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>'
        "<ports></ports></host>"
    )
    adapter.parse(_out(incomplete), "127.0.0.1", _req())
    assert adapter.coverage_loss(_out(incomplete), _req()) is not None
    clean = _nmaprun(
        '<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http"/></port></ports></host>'
        '<runstats><finished time="1" exit="success"/></runstats>'
    )
    adapter.parse(_out(clean), "127.0.0.1", _req())
    assert adapter.coverage_loss(_out(clean), _req()) is None
