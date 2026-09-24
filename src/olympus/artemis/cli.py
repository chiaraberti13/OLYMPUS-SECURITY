"""Command-line interface for scope-safe Artemis web reconnaissance.

Every command that touches a live target reports the same three things: the
findings, the *coverage* behind them, and an exit code derived from both. A
command that could not complete its work exits ``5`` (partial) or ``6``
(failed) rather than ``0``, because an empty findings list from a run that
never reached the target is the most misleading output a scanner can produce.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import typer

from olympus.artemis.application import ScopedFetchRequest, ScopedFetchService
from olympus.artemis.content import (
    WordlistError,
    classify_fetch_error,
    discover_content,
    discoveries_to_findings,
    load_wordlist,
)
from olympus.artemis.fingerprint import fingerprint_response, fingerprints_to_findings
from olympus.artemis.http import (
    HttpClientError,
    PinnedTransport,
    SocketResolver,
)
from olympus.artemis.metabase import detect_metabase
from olympus.artemis.scope import OutOfScopeError, ScopeError, enforce_scope
from olympus.artemis.xss import check_reflected_xss
from olympus.core.coverage import (
    Coverage,
    CoverageTracker,
    FailureKind,
    exit_code_for,
    summarize,
)
from olympus.core.enums import AssetType, Source
from olympus.core.execution import (
    AuthorizationRequiredError,
    CancellationRequested,
    ExecutionPolicy,
    ExecutionPolicyError,
)
from olympus.core.exit_codes import ExitCode
from olympus.core.models import Asset, Finding
from olympus.core.paths import audit_log_path

app = typer.Typer(help="Artemis — authorized web reconnaissance.", no_args_is_help=True)
DEFAULT_SCOPE = Path("examples/input/artemis-scope.json")
DEFAULT_LOG = audit_log_path("artemis-blocked.log")
DEFAULT_METABASE_SCOPE = Path("examples/input/artemis-metabase-scope.json")

# Shown before an active web test that sends requests to a live target.
_ACTIVE_DISCLAIMER = (
    "AUTHORIZED USE ONLY — this actively probes a live web target. Run it only against "
    "systems you are explicitly authorized to test (documented engagement/scope). "
    "Re-run with --i-am-authorized to confirm."
)


def _render_findings(findings: list[Finding]) -> str:
    """Render findings as pretty-printed, sorted JSON."""
    return json.dumps(
        [json.loads(finding.model_dump_json()) for finding in findings],
        indent=2,
        sort_keys=True,
    )


def _require_active_authorization(authorized: bool) -> ExecutionPolicy:
    policy = ExecutionPolicy(authorized=authorized, timeout_seconds=5.0, deadline_seconds=60.0)
    try:
        policy.require_authorization("Artemis live web probe")
    except AuthorizationRequiredError as exc:
        typer.echo(f"artemis: {_ACTIVE_DISCLAIMER}", err=True)
        raise typer.Exit(code=ExitCode.NOT_AUTHORIZED) from exc
    return policy


def _emit(findings: list[Finding], output: Path | None) -> None:
    """Print findings and, when asked, export the same document to disk."""
    rendered = _render_findings(findings)
    typer.echo(rendered)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")


def _finish(command: str, findings: list[Finding], coverage: Coverage) -> None:
    """Report coverage on stderr and exit with the status the run earned."""
    status = coverage.status(len(findings))
    typer.echo(f"artemis: {command} {summarize(status, coverage, len(findings))}", err=True)
    for sample in coverage.errors:
        typer.echo(f"artemis: {command} could not check {sample}", err=True)
    raise typer.Exit(code=exit_code_for(status))


@app.command()
def fetch(
    url: str = typer.Option(..., "--url"),
    scope: Path = typer.Option(DEFAULT_SCOPE, "--scope"),
    log: Path = typer.Option(DEFAULT_LOG, "--log"),
    timeout: float = typer.Option(5.0, "--timeout"),
    max_bytes: int = typer.Option(1_000_000, "--max-bytes"),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm documented authorization for this live fetch."
    ),
) -> None:
    """Perform one bounded, scope-safe GET flow and print metadata only."""
    try:
        result = ScopedFetchService(SocketResolver(), PinnedTransport()).run(
            ScopedFetchRequest(
                url=url,
                scope_path=scope,
                audit_log_path=log,
                authorized=i_am_authorized,
                timeout_seconds=timeout,
                max_bytes=max_bytes,
            )
        )
    except AuthorizationRequiredError as exc:
        typer.echo(f"artemis: {_ACTIVE_DISCLAIMER}", err=True)
        raise typer.Exit(code=ExitCode.NOT_AUTHORIZED) from exc
    except OutOfScopeError as exc:
        typer.echo(f"artemis: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=ExitCode.OUT_OF_SCOPE) from exc
    except ScopeError as exc:
        typer.echo(f"artemis: scope error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    except CancellationRequested as exc:
        typer.echo("artemis: fetch cancelled", err=True)
        raise typer.Exit(code=ExitCode.CANCELLED) from exc
    except (HttpClientError, ValueError) as exc:
        # The single request this command exists to make did not happen, so the
        # run failed; it is not a usage mistake by the operator.
        typer.echo(f"artemis: fetch failed: {exc}", err=True)
        raise typer.Exit(code=ExitCode.FAILED) from exc
    metadata = {
        "body_bytes": len(result.response.body),
        "final_url": result.response.url,
        "redirects": result.redirects,
        "status": result.response.status,
    }
    typer.echo(json.dumps(metadata, indent=2, sort_keys=True))


@app.command()
def fingerprint(
    url: str = typer.Option(..., "--url", help="Base URL to fetch once and fingerprint."),
    scope: Path = typer.Option(DEFAULT_SCOPE, "--scope"),
    log: Path = typer.Option(DEFAULT_LOG, "--log"),
    timeout: float = typer.Option(5.0, "--timeout"),
    max_bytes: int = typer.Option(1_000_000, "--max-bytes"),
    asset_id: str = typer.Option(
        "AST-ARTEMIS-FP-1", "--asset-id", help="core.Asset id to attach findings to."
    ),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm you are authorized to test this target."
    ),
    output: Path | None = typer.Option(None, "--output", help="Export findings JSON to this path."),
) -> None:
    """Identify the technology stack from one scope-safe GET (passive, no extra requests)."""
    try:
        result = ScopedFetchService(SocketResolver(), PinnedTransport()).run(
            ScopedFetchRequest(
                url=url,
                scope_path=scope,
                audit_log_path=log,
                authorized=i_am_authorized,
                timeout_seconds=timeout,
                max_bytes=max_bytes,
            )
        )
    except AuthorizationRequiredError as exc:
        typer.echo(f"artemis: {_ACTIVE_DISCLAIMER}", err=True)
        raise typer.Exit(code=ExitCode.NOT_AUTHORIZED) from exc
    except OutOfScopeError as exc:
        typer.echo(f"artemis: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=ExitCode.OUT_OF_SCOPE) from exc
    except ScopeError as exc:
        typer.echo(f"artemis: scope error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    except CancellationRequested as exc:
        typer.echo("artemis: fingerprint cancelled", err=True)
        raise typer.Exit(code=ExitCode.CANCELLED) from exc
    except (HttpClientError, ValueError) as exc:
        typer.echo(f"artemis: fingerprint failed: {exc}", err=True)
        tracker = CoverageTracker(1)
        tracker.fail(classify_fetch_error(exc), str(exc))
        _finish("fingerprint", [], tracker.build())

    fingerprints = fingerprint_response(result.response)
    findings = fingerprints_to_findings(asset_id, result.response.url, fingerprints)
    _emit(findings, output)
    products = ", ".join(f.product for f in fingerprints) or "no known technology"
    typer.echo(f"artemis: fingerprint identified {products}", err=True)
    tracker = CoverageTracker(1)
    tracker.complete()
    _finish("fingerprint", findings, tracker.build())


@app.command()
def content(
    url: str = typer.Option(..., "--url", help="Authorized base URL to discover paths under."),
    wordlist: Path = typer.Option(..., "--wordlist", help="Newline-delimited candidate paths."),
    scope: Path = typer.Option(DEFAULT_SCOPE, "--scope"),
    log: Path = typer.Option(DEFAULT_LOG, "--log"),
    timeout: float = typer.Option(5.0, "--timeout"),
    max_bytes: int = typer.Option(1_000_000, "--max-bytes"),
    rate: float = typer.Option(
        0.0, "--rate", help="Minimum seconds between requests (politeness throttle)."
    ),
    jitter: float = typer.Option(
        0.2,
        "--jitter",
        help="Fraction of --rate to randomize each wait by (0 disables), so pacing is "
        "not a metronome.",
    ),
    deadline: float | None = typer.Option(
        None, "--deadline", help="Overall budget for the whole run, in seconds."
    ),
    asset_id: str = typer.Option(
        "AST-ARTEMIS-CONTENT-1", "--asset-id", help="core.Asset id to attach findings to."
    ),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm you are authorized to test this target."
    ),
    output: Path | None = typer.Option(None, "--output", help="Export findings JSON to this path."),
) -> None:
    """Discover existing paths/files under an authorized base URL (real dirbusting).

    Every candidate is re-checked against scope before the request, so discovery
    only ever touches authorized origins/path-prefixes. GET-only, bounded,
    rate-limited with jitter, and stopped by one overall deadline — it
    discovers, it never exploits. Candidates that could not be checked are
    reported, so a failed run never looks like a clean one.
    """
    _require_active_authorization(i_am_authorized)
    try:
        words = load_wordlist(wordlist)
    except WordlistError as exc:
        typer.echo(f"artemis: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc

    try:
        policy = ExecutionPolicy(
            authorized=i_am_authorized,
            timeout_seconds=timeout,
            deadline_seconds=_content_deadline(deadline, timeout, rate, len(words)),
            min_interval_seconds=rate,
            jitter_ratio=jitter,
        )
        report = discover_content(
            url,
            words,
            scope,
            log,
            SocketResolver(),
            PinnedTransport(),
            max_bytes=max_bytes,
            policy=policy,
        )
    except ExecutionPolicyError as exc:
        typer.echo(f"artemis: invalid execution policy: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    except CancellationRequested as exc:
        typer.echo("artemis: content discovery cancelled", err=True)
        raise typer.Exit(code=ExitCode.CANCELLED) from exc
    findings = discoveries_to_findings(asset_id, report.discovered)
    _emit(findings, output)
    typer.echo(
        f"artemis: content discovery tried {len(words)} path(s), found {len(report.discovered)}",
        err=True,
    )
    _finish("content", findings, report.coverage)


def _content_deadline(requested: float | None, timeout: float, rate: float, words: int) -> float:
    """Derive one overall budget for a discovery run.

    The old default multiplied the per-request timeout by the wordlist length,
    so a 5000-word list authorized a seven-hour run. The derived default still
    scales with the work but stays inside a bound an operator can predict, and
    ``--deadline`` overrides it outright.
    """
    if requested is not None:
        return requested
    estimated = (timeout + rate) * max(words, 1)
    return min(3600.0, max(timeout, estimated))


@app.command("check-scope")
def check_scope(
    url: str = typer.Option(..., "--url"),
    scope: Path = typer.Option(DEFAULT_SCOPE, "--scope"),
    log: Path = typer.Option(DEFAULT_LOG, "--log"),
) -> None:
    """Validate URL authorization without performing a network request."""
    try:
        approved = enforce_scope(url, scope, log)
    except ScopeError as exc:
        typer.echo(f"artemis: scope error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    except OutOfScopeError as exc:
        typer.echo(f"artemis: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=ExitCode.OUT_OF_SCOPE) from exc
    typer.echo(f"artemis: authorized {approved.url} (no network request performed)")


@app.command()
def metabase(
    url: str = typer.Option(..., "--url", help="Base URL of the Metabase instance to fingerprint."),
    scope: Path = typer.Option(DEFAULT_METABASE_SCOPE, "--scope"),
    log: Path = typer.Option(DEFAULT_LOG, "--log"),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm you are authorized to test this target."
    ),
    output: Path | None = typer.Option(None, "--output", help="Export findings JSON to this path."),
) -> None:
    """Non-exploitatively check a Metabase instance for CVE-2026-72898 exposure.

    Reads the public version and endpoint reachability through the scope-safe,
    DNS-pinned transport. Never sends a SQL injection payload.
    """
    policy = _require_active_authorization(i_am_authorized)
    asset = Asset(
        asset_type=AssetType.WEB_SERVER,
        hostname=url,
        source=Source.ARTEMIS,
        tags=["artemis", "metabase"],
    )
    report = detect_metabase(
        asset.asset_id,
        url,
        scope,
        log,
        SocketResolver(),
        PinnedTransport(),
        policy=policy,
    )
    findings = list(report.findings)
    _emit(findings, output)
    typer.echo(f"artemis: metabase check produced {len(findings)} finding(s)", err=True)
    if report.coverage.complete and not report.identified:
        typer.echo("artemis: the target answered and is not a Metabase instance", err=True)
    _finish("metabase", findings, report.coverage)


def _target_params(url: str, param: str | None) -> list[str]:
    """Return the query parameters to test: the named one, or all in the URL."""
    if param is not None:
        return [param]
    return [key for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]


@app.command()
def xss(
    url: str = typer.Option(..., "--url", help="URL to probe (with query params to test)."),
    param: str | None = typer.Option(
        None, "--param", help="Parameter to test; if omitted, every query parameter is tested."
    ),
    scope: Path = typer.Option(DEFAULT_SCOPE, "--scope"),
    log: Path = typer.Option(DEFAULT_LOG, "--log"),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm you are authorized to test this target."
    ),
    output: Path | None = typer.Option(None, "--output", help="Export findings JSON to this path."),
) -> None:
    """Non-destructively test URL parameters for reflected XSS (marker reflection only).

    Sends a benign structural marker (no script/payload) through the scope-safe
    transport and flags an unescaped reflection. No WAF evasion is performed.
    """
    policy = _require_active_authorization(i_am_authorized)
    params = _target_params(url, param)
    if not params:
        typer.echo(
            "artemis: no query parameter to test (add one to the URL or use --param)", err=True
        )
        raise typer.Exit(code=ExitCode.USAGE)
    asset = Asset(
        asset_type=AssetType.WEB_SERVER,
        hostname=url,
        source=Source.ARTEMIS,
        tags=["artemis", "xss"],
    )
    resolver, transport = SocketResolver(), PinnedTransport()
    tracker = CoverageTracker(len(params))
    findings: list[Finding] = []
    for target in params:
        probe = check_reflected_xss(
            asset.asset_id,
            url,
            target,
            scope,
            log,
            resolver,
            transport,
            policy=policy,
        )
        if probe.completed:
            tracker.complete()
            findings.extend(probe.findings)
        else:
            tracker.fail(probe.failure or FailureKind.ERROR, probe.detail)
    _emit(findings, output)
    typer.echo(
        f"artemis: xss check tested {len(params)} param(s), {len(findings)} finding(s)", err=True
    )
    _finish("xss", findings, tracker.build())
