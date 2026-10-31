"""Bounded, non-destructive TCP surface discovery with explicit port states.

A boolean "is the port open" collapses five very different answers into one:
a refused connection, a silently dropped packet, a name that does not resolve,
a host with no route to it, and a probe the policy never allowed. An operator
reading "closed" for all five draws the wrong conclusion four times, so every
probe returns a :class:`PortState` instead.

Discovery stays non-destructive: Helios completes a TCP handshake and, when
banner reading is explicitly enabled, reads what the server volunteers. It
never sends application data.
"""

from __future__ import annotations

import errno
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from olympus.core.coverage import Coverage, CoverageTracker, FailureKind
from olympus.core.execution import (
    Cancellation,
    CancellationRequested,
    Deadline,
    ExecutionPolicy,
    NeverCancelled,
    redact_text,
)

#: Ports whose probes may be reported; a scan is a bounded, reviewable action.
MAX_PORTS = 128

#: Largest banner Helios will read from a service that greets first.
MAX_BANNER_BYTES = 256


class PortState(StrEnum):
    """The distinguishable outcomes of one bounded TCP probe."""

    #: The handshake completed: something is listening.
    OPEN = "open"
    #: The peer actively refused the connection: nothing is listening.
    CLOSED = "closed"
    #: No answer within the timeout — dropped by a filter, or simply slow.
    FILTERED = "filtered"
    #: The host or network has no route (ICMP unreachable, ENETUNREACH).
    UNREACHABLE = "unreachable"
    #: The target name could not be resolved.
    DNS_FAILURE = "dns_failure"
    #: A policy or scope gate refused this probe before it was sent.
    DENIED = "denied"
    #: The probe was not attempted: the run's deadline was already spent.
    DEADLINE_EXCEEDED = "deadline_exceeded"
    #: Anything else, kept explicit rather than folded into "closed".
    ERROR = "error"


#: States that mean the probe produced a trustworthy answer about the port.
_CONCLUSIVE: frozenset[PortState] = frozenset({PortState.OPEN, PortState.CLOSED})

#: States reached without sending a probe: counted as skipped, not failed.
_NEVER_ATTEMPTED: frozenset[PortState] = frozenset({PortState.DENIED, PortState.DEADLINE_EXCEEDED})

#: How each inconclusive state is accounted for in the run's coverage.
_FAILURE_KINDS: dict[PortState, FailureKind] = {
    PortState.FILTERED: FailureKind.TIMEOUT,
    PortState.UNREACHABLE: FailureKind.UNREACHABLE,
    PortState.DNS_FAILURE: FailureKind.DNS_FAILURE,
    PortState.DENIED: FailureKind.POLICY_DENIED,
    PortState.DEADLINE_EXCEEDED: FailureKind.DEADLINE_EXCEEDED,
    PortState.ERROR: FailureKind.TRANSPORT_ERROR,
}

#: OS errors that mean the packet never reached a listening stack.
_UNREACHABLE_ERRNOS: frozenset[int] = frozenset(
    code
    for code in (
        getattr(errno, name, None)
        for name in ("EHOSTUNREACH", "ENETUNREACH", "ENETDOWN", "EHOSTDOWN", "ENONET")
    )
    if code is not None
)


@dataclass(frozen=True)
class ProbeResult:
    """The outcome of one bounded TCP probe against a single port."""

    host: str
    port: int
    state: PortState
    service: str = "unknown"
    #: Product identified from a volunteered banner, when banner reading is on.
    product: str | None = None
    #: Redacted, bounded explanation for an inconclusive state.
    detail: str | None = None

    @property
    def conclusive(self) -> bool:
        """Whether this probe answered the question it was asked."""
        return self.state in _CONCLUSIVE


class Connector(Protocol):
    """TCP connection probe abstraction."""

    def probe(self, host: str, port: int, timeout: float) -> ProbeResult:
        """Return the outcome of one bounded TCP connection attempt."""
        ...


# Well-known TCP services, identified passively from the port number alone.
# Port numbers are a convention, not evidence: a banner (when enabled)
# overrides this guess.
_SERVICE_NAMES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}

# Services that are risky to expose to untrusted networks (cleartext admin,
# databases, remote desktop...). Everything else is informational.
_RISKY_SERVICES: frozenset[str] = frozenset(
    {
        "telnet",
        "ftp",
        "rdp",
        "vnc",
        "smb",
        "mssql",
        "mysql",
        "postgres",
        "redis",
        "mongodb",
        "elasticsearch",
        "oracle",
        "nfs",
    }
)

# Banner shapes for protocols where the *server* speaks first. Helios only
# reads; it never sends a probe string, so protocols that wait for the client
# (HTTP, TLS...) are deliberately absent — identifying those would require
# sending application data, which is not what this tool does.
_BANNER_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ssh", re.compile(r"^SSH-\d+\.\d+-(?P<product>\S+)")),
    ("smtp", re.compile(r"^220[- ].*?\b(?P<product>Postfix|Exim|Sendmail|Microsoft ESMTP)")),
    ("smtp", re.compile(r"^220[- ]")),
    ("ftp", re.compile(r"^220[- ].*?\b(?P<product>vsFTPd|ProFTPD|FileZilla|Pure-FTPd)")),
    ("ftp", re.compile(r"^220[- ].*FTP", re.IGNORECASE)),
    ("pop3", re.compile(r"^\+OK\s*(?P<product>\S+)?")),
    ("imap", re.compile(r"^\* OK\s*(?P<product>\S+)?")),
    ("mysql", re.compile(r"^.?\x00*(?P<product>\d+\.\d+\.\d+)[-\w.]*")),
)

#: Control characters a hostile banner could use to corrupt a terminal or log.
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def service_for(port: int) -> str:
    """Return the well-known service name for ``port``, or ``"unknown"``."""
    return _SERVICE_NAMES.get(port, "unknown")


def is_risky(service: str) -> bool:
    """Return whether exposing ``service`` to untrusted networks is risky."""
    return service in _RISKY_SERVICES


def sanitize_banner(raw: bytes) -> str:
    """Return a bounded, control-character-free rendering of a server banner.

    Banner bytes come from the target, so they are hostile input: they are
    truncated, decoded without raising, and stripped of anything that could
    rewrite a terminal or forge a log line.
    """
    text = raw[:MAX_BANNER_BYTES].decode("utf-8", errors="replace")
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return _CONTROL_CHARACTERS.sub("", text).strip()


def identify_banner(banner: str) -> tuple[str | None, str | None]:
    """Return ``(service, product)`` identified from a volunteered banner.

    Both are ``None`` when the banner matches nothing known, which is a real
    answer: a port number guess is not upgraded into a claim.
    """
    if not banner:
        return None, None
    for service, pattern in _BANNER_SIGNATURES:
        match = pattern.match(banner)
        if match is None:
            continue
        product = match.groupdict().get("product") if match.groupdict() else None
        return service, (product or None)
    return None, None


class SocketConnector:
    """Production connector using one bounded TCP handshake per port.

    With ``read_banner`` enabled it also reads (never writes) up to
    :data:`MAX_BANNER_BYTES` from services that greet first, so the reported
    service is evidence rather than a port-number guess. Reading is strictly
    opt-in: a bare handshake is the quieter, default behavior.
    """

    def __init__(self, read_banner: bool = False, banner_timeout: float = 1.0) -> None:
        if not 0.05 <= banner_timeout <= 10.0:
            raise ValueError("banner_timeout must be between 0.05 and 10 seconds")
        self.read_banner = read_banner
        self.banner_timeout = banner_timeout

    def probe(self, host: str, port: int, timeout: float) -> ProbeResult:
        service = service_for(port)
        try:
            with socket.create_connection((host, port), timeout=timeout) as connection:
                product = None
                if self.read_banner:
                    service, product = self._read_banner(connection, service)
                return ProbeResult(host, port, PortState.OPEN, service, product)
        except socket.gaierror as exc:
            return self._failed(host, port, service, PortState.DNS_FAILURE, exc)
        except TimeoutError as exc:
            return self._failed(host, port, service, PortState.FILTERED, exc)
        except ConnectionRefusedError as exc:
            return self._failed(host, port, service, PortState.CLOSED, exc)
        except OSError as exc:
            state = PortState.UNREACHABLE if exc.errno in _UNREACHABLE_ERRNOS else PortState.ERROR
            return self._failed(host, port, service, state, exc)

    def _read_banner(self, connection: socket.socket, service: str) -> tuple[str, str | None]:
        """Read only what the server volunteers; never send application data."""
        try:
            connection.settimeout(self.banner_timeout)
            raw = connection.recv(MAX_BANNER_BYTES)
        except OSError:
            return service, None  # a silent service is not an error, just quiet
        identified, product = identify_banner(sanitize_banner(raw))
        return identified or service, product

    @staticmethod
    def _failed(host: str, port: int, service: str, state: PortState, exc: OSError) -> ProbeResult:
        return ProbeResult(
            host, port, state, service, detail=redact_text(str(exc))[:200] or state.value
        )


@dataclass(frozen=True)
class SurfaceScanReport:
    """Every probe of one scan, plus what the scan could and could not answer."""

    probes: tuple[ProbeResult, ...]
    coverage: Coverage

    @property
    def open_ports(self) -> tuple[ProbeResult, ...]:
        """Probes that found something listening."""
        return tuple(probe for probe in self.probes if probe.state is PortState.OPEN)


def normalize_ports(ports: list[int]) -> tuple[int, ...]:
    """Validate, deduplicate, and sort a bounded TCP port set."""
    normalized = tuple(sorted(set(ports)))
    invalid_port = any(not 1 <= port <= 65535 for port in normalized)
    if not normalized or len(normalized) > MAX_PORTS or invalid_port:
        raise ValueError(f"ports must contain 1 to {MAX_PORTS} values in the range 1..65535")
    return normalized


def discover(
    host: str,
    ports: list[int],
    connector: Connector,
    *,
    policy: ExecutionPolicy | None = None,
    cancellation: Cancellation | None = None,
    allowed_ports: frozenset[int] | None = None,
) -> SurfaceScanReport:
    """Probe a bounded port set with limited concurrency, a deadline and cancellation.

    Probes run on at most ``policy.max_concurrency`` threads. The overall
    deadline is taken once and shared: ports the run never reaches are recorded
    as :attr:`PortState.DEADLINE_EXCEEDED` rather than silently dropped, so a
    truncated scan can never read as a clean one. Ports outside ``allowed_ports``
    are reported as :attr:`PortState.DENIED` and never touched.
    """
    normalized = normalize_ports(ports)
    active = policy or ExecutionPolicy(authorized=True)
    if not 0.05 <= active.timeout_seconds <= 10.0:
        raise ValueError("timeout must be between 0.05 and 10 seconds")
    token = cancellation or NeverCancelled()
    deadline = Deadline(active.deadline_seconds)
    tracker = CoverageTracker(len(normalized))

    probes = _run_probes(host, normalized, connector, active, token, deadline, allowed_ports)
    for probe in probes:
        if probe.conclusive:
            tracker.complete()
        elif probe.state in _NEVER_ATTEMPTED:
            # Refused or out of budget: the probe was never sent, so it is a
            # gap in coverage rather than an attempt that failed.
            tracker.skip(_FAILURE_KINDS[probe.state], probe.detail)
        else:
            tracker.fail(_FAILURE_KINDS[probe.state], probe.detail)
    if token.is_cancelled():
        raise CancellationRequested("operation cancelled")
    return SurfaceScanReport(probes, tracker.build())


def _run_probes(
    host: str,
    ports: tuple[int, ...],
    connector: Connector,
    policy: ExecutionPolicy,
    token: Cancellation,
    deadline: Deadline,
    allowed_ports: frozenset[int] | None,
) -> tuple[ProbeResult, ...]:
    """Dispatch every port probe under the shared deadline and cancellation token."""

    def probe_one(port: int) -> ProbeResult:
        service = service_for(port)
        if allowed_ports is not None and port not in allowed_ports:
            return ProbeResult(
                host, port, PortState.DENIED, service, detail="port not in engagement scope"
            )
        if token.is_cancelled():
            return ProbeResult(host, port, PortState.DENIED, service, detail="cancelled")
        remaining = deadline.remaining
        if remaining < 0.05:
            return ProbeResult(
                host, port, PortState.DEADLINE_EXCEEDED, service, detail="run deadline reached"
            )
        return connector.probe(host, port, min(policy.timeout_seconds, remaining))

    if policy.max_concurrency <= 1:
        return tuple(probe_one(port) for port in ports)
    with ThreadPoolExecutor(max_workers=policy.max_concurrency) as pool:
        return tuple(pool.map(probe_one, ports))
