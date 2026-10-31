"""Non-destructive reflected-XSS *reflection* check for Artemis.

This probes a single URL parameter with a benign, unique marker that contains
the HTML-significant characters ``' " < >`` — but **no** script, event handler
or executable payload. If those characters come back **unescaped** in the
response body, the parameter reflects unsanitized input and is very likely
injectable; if they come back HTML-encoded, the app is escaping correctly and
nothing is flagged.

Deliberate safety choices (unlike the source tool this concept comes from):
- The marker is structural only — it never tries to execute anything.
- **No** WAF detection/evasion, no browser automation, no payload lists.
- One scoped GET through Artemis's DNS-pinned :func:`fetch_scoped` transport.
It is a first-pass reflection check: a positive result warrants manual
confirmation of the injection context.

A probe that never reached the parameter is reported as a failure, not as "no
reflection found": those two answers look identical in a findings list and mean
opposite things.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from olympus.artemis.content import classify_fetch_error
from olympus.artemis.http import HttpClientError, Resolver, Transport, fetch_scoped
from olympus.artemis.scope import OutOfScopeError, ScopeError
from olympus.core.coverage import FailureKind
from olympus.core.enums import Severity, Source
from olympus.core.execution import ExecutionPolicy
from olympus.core.models import Finding

# Unique, non-executable marker carrying HTML-significant characters only.
MARKER = "olymp7xss'\"<>"
OWASP_REFERENCE = "https://owasp.org/www-community/attacks/xss/"


def _inject(url: str, param: str, value: str) -> str:
    """Return ``url`` with query parameter ``param`` set to ``value``."""
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[param] = value
    new_query = urlencode(query)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


@dataclass(frozen=True)
class XssProbeResult:
    """The outcome of probing one parameter: a finding, a clean read, or a failure."""

    param: str
    findings: tuple[Finding, ...] = ()
    #: ``None`` when the probe completed; otherwise why it could not.
    failure: FailureKind | None = None
    detail: str | None = None

    @property
    def completed(self) -> bool:
        """Whether this probe actually observed the parameter's behavior."""
        return self.failure is None


def check_reflected_xss(
    asset_id: str,
    url: str,
    param: str,
    scope_path: Path,
    log_path: Path,
    resolver: Resolver,
    transport: Transport,
    *,
    policy: ExecutionPolicy,
) -> XssProbeResult:
    """Probe ``param`` on ``url`` for an unescaped reflection of the benign marker."""
    probed = _inject(url, param, MARKER)
    try:
        result = fetch_scoped(probed, scope_path, log_path, resolver, transport, policy=policy)
    except (HttpClientError, ScopeError, OutOfScopeError, ValueError) as exc:
        return XssProbeResult(param, failure=classify_fetch_error(exc), detail=f"{param}: {exc}")

    body = result.response.body.decode("utf-8", errors="replace")
    if MARKER not in body:
        # Not reflected at all, or reflected only in an HTML-escaped form -> not flagged.
        return XssProbeResult(param)

    finding = Finding(
        asset_id=asset_id,
        source=Source.ARTEMIS,
        title=f"Reflected XSS: parameter '{param}' reflects input unescaped",
        description=(
            f"A benign marker containing the characters ' \" < > was reflected verbatim "
            f"(unescaped) in the response for parameter '{param}', indicating the value is "
            "not contextually output-encoded. This is very likely exploitable as reflected "
            "cross-site scripting. No executable payload was sent — only structural "
            "characters — so manual confirmation of the injection context is recommended."
        ),
        severity=Severity.HIGH,
        evidence=[f"GET {probed}", f"reflected marker: {MARKER}"],
        remediation=(
            "Apply contextual output encoding for the reflection context (HTML body, "
            "attribute, JS, URL) and add a restrictive Content-Security-Policy."
        ),
        references=[OWASP_REFERENCE],
    )
    return XssProbeResult(param, findings=(finding,))
