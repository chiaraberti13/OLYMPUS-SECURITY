"""Tests for bounded and scoped Helios surface discovery."""

import errno
import json
import socket
import threading
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.coverage import FailureKind, RunStatus
from olympus.core.execution import (
    AuthorizationRequiredError,
    CancellationRequested,
    CancellationToken,
    ExecutionPolicy,
)
from olympus.core.models import Finding, Observation
from olympus.helios import cli as helios_cli
from olympus.helios.application import SurfaceScanRequest, SurfaceScanService
from olympus.helios.export import export_findings, to_findings, to_observations
from olympus.helios.scanner import (
    PortState,
    ProbeResult,
    SocketConnector,
    discover,
    identify_banner,
    sanitize_banner,
)
from olympus.helios.scope import OutOfScopeError, ScopeError, enforce_scope


class FakeConnector:
    """Reports 443 open on the demo host; everything else refused."""

    def __init__(self, read_banner: bool = False) -> None:
        self.read_banner = read_banner
        self.calls: list[tuple[str, int, float]] = []

    def probe(self, host: str, port: int, timeout: float) -> ProbeResult:
        self.calls.append((host, port, timeout))
        if host == "192.0.2.10" and port == 443:
            return ProbeResult(host, port, PortState.OPEN, "https")
        return ProbeResult(host, port, PortState.CLOSED, "http", detail="refused")


class StateConnector:
    """Returns a caller-provided state for every port."""

    def __init__(self, state: PortState, detail: str = "") -> None:
        self.state = state
        self.detail = detail

    def probe(self, host: str, port: int, timeout: float) -> ProbeResult:
        del timeout
        return ProbeResult(host, port, self.state, "https", detail=self.detail or None)


runner = CliRunner()


def _scope(path: Path, **extra: object) -> Path:
    payload: dict[str, object] = {"allowed_networks": ["192.0.2.0/24", "2001:db8::/32"]}
    payload.update(extra)
    path.write_text(json.dumps(payload))
    return path


def test_scope_accepts_ipv4_and_ipv6_and_logs_blocks(tmp_path: Path) -> None:
    scope = _scope(tmp_path / "scope.json")
    log = tmp_path / "blocked.log"

    assert str(enforce_scope("192.0.2.10", scope, log).address) == "192.0.2.10"
    assert str(enforce_scope("2001:db8::10", scope, log).address) == "2001:db8::10"
    with pytest.raises(OutOfScopeError):
        enforce_scope("203.0.113.10", scope, log)
    audit = json.loads(log.read_text(encoding="utf-8"))
    assert audit["action"] == "helios.scope"
    assert audit["outcome"] == "blocked"
    assert audit["target"] == "203.0.113.10"


def test_scope_reads_optional_port_allowlist(tmp_path: Path) -> None:
    scope = _scope(tmp_path / "scope.json", allowed_ports=[443])
    decision = enforce_scope("192.0.2.10", scope, tmp_path / "blocked.log")

    assert decision.allowed_ports == frozenset({443})
    assert decision.permits(443) is True
    assert decision.permits(22) is False


def test_scope_rejects_a_malformed_port_allowlist(tmp_path: Path) -> None:
    scope = _scope(tmp_path / "scope.json", allowed_ports=[0])
    with pytest.raises(ScopeError):
        enforce_scope("192.0.2.10", scope, tmp_path / "blocked.log")


def test_scope_without_a_port_allowlist_permits_every_port(tmp_path: Path) -> None:
    decision = enforce_scope("192.0.2.10", _scope(tmp_path / "s.json"), tmp_path / "b.log")
    assert decision.allowed_ports is None
    assert decision.permits(65535) is True


def test_discovery_is_bounded_and_injectable() -> None:
    report = discover("192.0.2.10", [443, 80, 443], FakeConnector())

    assert [(p.port, p.state) for p in report.probes] == [
        (80, PortState.CLOSED),
        (443, PortState.OPEN),
    ]
    assert report.open_ports == (ProbeResult("192.0.2.10", 443, PortState.OPEN, "https"),)
    with pytest.raises(ValueError):
        discover("192.0.2.10", [0], FakeConnector())
    with pytest.raises(ValueError):
        discover("192.0.2.10", list(range(1, 130)), FakeConnector())


def test_closed_and_open_ports_both_count_as_full_coverage() -> None:
    report = discover("192.0.2.10", [80, 443], FakeConnector())

    assert report.coverage.planned == 2
    assert report.coverage.completed == 2
    assert report.coverage.complete is True
    assert report.coverage.status(1) is RunStatus.FINDINGS
    assert report.coverage.status(0) is RunStatus.CLEAN


@pytest.mark.parametrize(
    ("state", "kind"),
    [
        (PortState.FILTERED, FailureKind.TIMEOUT),
        (PortState.UNREACHABLE, FailureKind.UNREACHABLE),
        (PortState.DNS_FAILURE, FailureKind.DNS_FAILURE),
        (PortState.ERROR, FailureKind.TRANSPORT_ERROR),
    ],
)
def test_inconclusive_states_never_read_as_a_clean_scan(
    state: PortState, kind: FailureKind
) -> None:
    report = discover("192.0.2.10", [80, 443], StateConnector(state, "why"))

    assert report.coverage.completed == 0
    assert report.coverage.reasons == {kind: 2}
    assert report.coverage.status(0) is RunStatus.FAILED
    assert report.open_ports == ()


def test_partial_coverage_outranks_findings() -> None:
    class Mixed:
        def probe(self, host: str, port: int, timeout: float) -> ProbeResult:
            del timeout
            if port == 443:
                return ProbeResult(host, port, PortState.OPEN, "https")
            return ProbeResult(host, port, PortState.FILTERED, "ssh", detail="timed out")

    report = discover("192.0.2.10", [22, 443], Mixed())

    assert report.coverage.completed == 1
    assert report.coverage.failed == 1
    assert report.coverage.status(1) is RunStatus.PARTIAL


def test_ports_outside_the_engagement_allowlist_are_never_probed(tmp_path: Path) -> None:
    connector = FakeConnector()
    report = discover("192.0.2.10", [22, 443], connector, allowed_ports=frozenset({443}))

    assert [call[1] for call in connector.calls] == [443]
    denied = next(probe for probe in report.probes if probe.port == 22)
    assert denied.state is PortState.DENIED
    assert report.coverage.reasons == {FailureKind.POLICY_DENIED: 1}
    # Never sent, so it is a gap in coverage rather than a failed attempt.
    assert report.coverage.skipped == 1
    assert report.coverage.failed == 0


def test_deadline_stops_a_scan_without_pretending_the_rest_was_clean() -> None:
    class Slow:
        def probe(self, host: str, port: int, timeout: float) -> ProbeResult:
            del timeout
            import time

            time.sleep(0.12)
            return ProbeResult(host, port, PortState.CLOSED, "http")

    policy = ExecutionPolicy(authorized=True, timeout_seconds=0.05, deadline_seconds=0.15)
    report = discover("192.0.2.10", [80, 443, 8080], Slow(), policy=policy)

    skipped = [p for p in report.probes if p.state is PortState.DEADLINE_EXCEEDED]
    assert skipped, [p.state for p in report.probes]
    assert report.coverage.reasons[FailureKind.DEADLINE_EXCEEDED] == len(skipped)
    assert report.coverage.status(0) is not RunStatus.CLEAN


def test_bounded_concurrency_probes_every_port_once() -> None:
    seen: list[int] = []
    lock = threading.Lock()

    class Threaded:
        def probe(self, host: str, port: int, timeout: float) -> ProbeResult:
            del timeout
            with lock:
                seen.append(port)
            return ProbeResult(host, port, PortState.CLOSED, "http")

    policy = ExecutionPolicy(authorized=True, timeout_seconds=1.0, max_concurrency=4)
    report = discover("192.0.2.10", [80, 443, 8080, 9000], Threaded(), policy=policy)

    assert sorted(seen) == [80, 443, 8080, 9000]
    assert [probe.port for probe in report.probes] == [80, 443, 8080, 9000]
    assert report.coverage.complete is True


def test_cancellation_between_probes_is_surfaced() -> None:
    token = CancellationToken()
    token.cancel()
    with pytest.raises(CancellationRequested):
        discover("192.0.2.10", [80], FakeConnector(), cancellation=token)


def test_socket_connector_classifies_os_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    cases = {
        ConnectionRefusedError(errno.ECONNREFUSED, "refused"): PortState.CLOSED,
        TimeoutError("timed out"): PortState.FILTERED,
        socket.gaierror(-2, "Name or service not known"): PortState.DNS_FAILURE,
        OSError(errno.EHOSTUNREACH, "no route to host"): PortState.UNREACHABLE,
        OSError(errno.EACCES, "permission denied"): PortState.ERROR,
    }
    for raised, expected in cases.items():

        def connect(*args: object, raised: BaseException = raised, **kwargs: object) -> None:
            raise raised

        monkeypatch.setattr(socket, "create_connection", connect)
        probe = SocketConnector().probe("192.0.2.10", 443, 0.5)
        assert probe.state is expected, raised
        assert probe.conclusive is (expected is PortState.CLOSED)
        assert probe.detail


def test_banner_reading_is_opt_in_and_never_sends_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[bytes] = []

    class FakeSocket:
        def __enter__(self) -> "FakeSocket":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def settimeout(self, value: float) -> None:
            del value

        def recv(self, size: int) -> bytes:
            del size
            return b"SSH-2.0-OpenSSH_9.6p1 Debian\r\n"

        def sendall(self, payload: bytes) -> None:  # pragma: no cover - must never run
            sent.append(payload)

    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: FakeSocket())

    quiet = SocketConnector().probe("192.0.2.10", 2222, 0.5)
    assert quiet.service == "unknown"  # port 2222 has no well-known mapping
    assert quiet.product is None

    identified = SocketConnector(read_banner=True).probe("192.0.2.10", 2222, 0.5)
    assert identified.service == "ssh"
    assert identified.product == "OpenSSH_9.6p1"
    assert sent == []


def test_banner_reading_survives_a_silent_service(monkeypatch: pytest.MonkeyPatch) -> None:
    class Silent:
        def __enter__(self) -> "Silent":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def settimeout(self, value: float) -> None:
            del value

        def recv(self, size: int) -> bytes:
            del size
            raise TimeoutError("nothing volunteered")

    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: Silent())
    probe = SocketConnector(read_banner=True).probe("192.0.2.10", 443, 0.5)

    assert probe.state is PortState.OPEN
    assert probe.service == "https"  # falls back to the port-number guess
    assert probe.product is None


def test_banner_text_is_sanitized_before_it_reaches_a_report() -> None:
    raw = b"220 \x1b[2Jmail.example ESMTP Postfix\r\n" + b"A" * 1000
    banner = sanitize_banner(raw)

    assert "\x1b" not in banner
    assert "\r" not in banner and "\n" not in banner
    assert len(banner) <= 256
    assert identify_banner(banner) == ("smtp", "Postfix")


def test_identify_banner_returns_nothing_for_unknown_greetings() -> None:
    assert identify_banner("HELLO CUSTOM PROTOCOL") == (None, None)
    assert identify_banner("") == (None, None)


def test_surface_service_authorizes_and_scopes_before_connector(tmp_path: Path) -> None:
    connector = FakeConnector()
    scope = _scope(tmp_path / "scope.json")
    request = SurfaceScanRequest(
        target="192.0.2.10",
        ports=(443,),
        scope_path=scope,
        audit_log_path=tmp_path / "audit.log",
        asset_id="AST-1",
    )

    with pytest.raises(AuthorizationRequiredError):
        SurfaceScanService(connector).run(request)
    assert connector.calls == []

    with pytest.raises(OutOfScopeError):
        SurfaceScanService(connector).run(replace(request, target="203.0.113.10", authorized=True))
    assert connector.calls == []


def test_surface_service_observes_cancellation_before_connector(tmp_path: Path) -> None:
    connector = FakeConnector()
    token = CancellationToken()
    token.cancel()

    with pytest.raises(CancellationRequested):
        SurfaceScanService(connector, token).run(
            SurfaceScanRequest(
                target="192.0.2.10",
                ports=(443,),
                scope_path=_scope(tmp_path / "scope.json"),
                audit_log_path=tmp_path / "audit.log",
                asset_id="AST-1",
                authorized=True,
            )
        )
    assert connector.calls == []


def test_surface_service_audits_ports_the_engagement_refused(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    outcome = SurfaceScanService(FakeConnector()).run(
        SurfaceScanRequest(
            target="192.0.2.10",
            ports=(22, 443),
            scope_path=_scope(tmp_path / "scope.json", allowed_ports=[443]),
            audit_log_path=log,
            asset_id="AST-1",
            authorized=True,
        )
    )

    assert outcome.status is RunStatus.PARTIAL
    record = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    assert record["metadata"] == {"reason": "port_not_allowed", "ports": [22]}


def test_surface_service_deadline_does_not_grow_with_the_port_count(tmp_path: Path) -> None:
    request = SurfaceScanRequest(
        target="192.0.2.10",
        ports=tuple(range(1, 101)),
        scope_path=_scope(tmp_path / "scope.json"),
        audit_log_path=tmp_path / "audit.log",
        asset_id="AST-1",
        authorized=True,
        timeout_seconds=10.0,
        max_concurrency=10,
    )
    derived = SurfaceScanService._deadline_for(request, 100)

    assert derived == 100.0  # 10 lanes x 10 rounds, not 100 x 10s
    assert derived <= 300.0


def test_findings_round_trip_through_core(tmp_path: Path) -> None:
    output = tmp_path / "helios-findings.json"
    export_findings(
        to_findings("AST-2026-00001", [ProbeResult("192.0.2.10", 443, PortState.OPEN, "https")]),
        output,
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    findings = [Finding.model_validate(item) for item in payload["findings"]]
    assert findings[0].evidence == ["tcp://192.0.2.10:443 (https)"]


def test_service_identification_and_risk() -> None:
    from olympus.helios.scanner import is_risky, service_for

    assert service_for(3389) == "rdp"
    assert service_for(65000) == "unknown"
    assert is_risky("rdp") is True
    assert is_risky("https") is False


def test_findings_flag_risky_services() -> None:
    from olympus.core.enums import Severity

    findings = to_findings("AST-1", [ProbeResult("10.0.0.1", 3389, PortState.OPEN, "rdp")])
    assert findings[0].severity is Severity.MEDIUM
    assert "high-risk" in findings[0].description
    assert findings[0].remediation


def test_findings_are_produced_only_for_open_ports() -> None:
    probes = [
        ProbeResult("10.0.0.1", 22, PortState.FILTERED, "ssh", detail="timed out"),
        ProbeResult("10.0.0.1", 443, PortState.OPEN, "https"),
    ]
    assert [f.title for f in to_findings("AST-1", probes)] == [
        "TCP port 443 exposed (https)",
    ]


def test_findings_carry_the_banner_product_as_evidence() -> None:
    probe = ProbeResult("10.0.0.1", 2222, PortState.OPEN, "ssh", product="OpenSSH_9.6p1")
    finding = to_findings("AST-1", [probe])[0]

    assert "OpenSSH_9.6p1" in finding.title
    assert "banner identified: OpenSSH_9.6p1" in finding.evidence


def test_discover_sets_service() -> None:
    report = discover("192.0.2.10", [443], FakeConnector())
    assert report.open_ports and report.open_ports[0].service == "https"


def test_cli_scan_enforces_scope_and_exports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helios_cli, "SocketConnector", FakeConnector)
    scope = _scope(tmp_path / "scope.json")
    output = tmp_path / "findings.json"

    result = runner.invoke(
        app,
        [
            "helios",
            "scan",
            "192.0.2.10",
            "--ports",
            "80,443",
            "--scope",
            str(scope),
            "--output",
            str(output),
            "--log",
            str(tmp_path / "blocked.log"),
            "--i-am-authorized",
        ],
    )

    assert result.exit_code == 1, result.output  # an exposed port is a finding
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_name"] == "olympus.helios-result"
    assert payload["schema_version"] == "1.1.0"
    assert payload["status"] == "findings"
    assert payload["coverage"]["completed"] == 2
    assert payload["coverage"]["complete"] is True
    observations = {
        item["attributes"]["port"]: item["attributes"] for item in payload["observations"]
    }
    assert observations["443"]["state"] == "open"
    assert observations["80"]["state"] == "closed"
    parsed = [Observation.model_validate(item) for item in payload["observations"]]
    assert {item.observation_type for item in parsed} == {"tcp.open-port", "tcp.port-probe"}


def test_cli_scan_exits_partial_when_coverage_is_lost(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        helios_cli,
        "SocketConnector",
        lambda read_banner=False: StateConnector(PortState.FILTERED, "timed out"),
    )
    output = tmp_path / "findings.json"
    result = runner.invoke(
        app,
        [
            "helios",
            "scan",
            "192.0.2.10",
            "--ports",
            "80,443",
            "--scope",
            str(_scope(tmp_path / "scope.json")),
            "--output",
            str(output),
            "--log",
            str(tmp_path / "blocked.log"),
            "--i-am-authorized",
        ],
    )

    assert result.exit_code == 6, result.output  # nothing was answered at all
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "failed"
    assert "status=failed" in result.output


def test_open_ports_map_to_versioned_observations() -> None:
    observations = to_observations(
        "AST-2026-00001", [ProbeResult("192.0.2.10", 443, PortState.OPEN, "https")]
    )
    assert observations[0].schema_name == "olympus.observation"
    assert observations[0].observation_type == "tcp.open-port"
    assert observations[0].attributes["state"] == "open"


def test_cli_scan_requires_explicit_authorization(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["helios", "scan", "192.0.2.10", "--scope", str(_scope(tmp_path / "scope.json"))],
    )
    assert result.exit_code == 4
