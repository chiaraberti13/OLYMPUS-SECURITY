"""Command-line interface for the Argus module."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from olympus.argus.accounts import (
    AccountIntel,
    SiteRegistryError,
    load_site_registry,
    validate_public_site_url,
)
from olympus.argus.accounts_scope import (
    AccountOutOfScopeError,
    AccountScopeError,
)
from olympus.argus.application import (
    AccountEnumerationRequest,
    AccountEnumerationService,
    ArgusDiagnosticsService,
    AuthorizationRequiredError,
    DnsLookupRequest,
    DnsLookupService,
    DomainScanRequest,
    DomainScanService,
    EmailAnalysisRequest,
    EmailAnalysisService,
    FrontingAssessmentRequest,
    FrontingAssessmentService,
    InvalidWebTargetError,
    InvestigationRequest,
    InvestigationService,
    IpProfileRequest,
    IpProfileService,
    MacAnalysisRequest,
    MacAnalysisService,
    MyIpDiscoveryRequest,
    MyIpDiscoveryService,
    PhoneProfileRequest,
    PhoneProfileService,
    SnapshotDiffService,
    WebReconRequest,
    WebReconService,
    WhoisLookupRequest,
    WhoisLookupService,
    authorize_web_url,
    web_address_policy,
)
from olympus.argus.assets import export_assets, recon_to_assets
from olympus.argus.ct import CertificateTransparencyError, CrtShClient
from olympus.argus.dns_records import (
    RECORD_TYPES,
    DnsRecordError,
    build_dns_asset,
    export_dns_report,
)
from olympus.argus.email_osint import (
    EmailParseError,
    export_email_intel,
)
from olympus.argus.enrichment import (
    HudsonRockBreachClient,
    NumverifyClient,
    RapidApiMessagingClient,
)
from olympus.argus.fronting import (
    export_fronting,
    report_to_asset,
    report_to_findings,
)
from olympus.argus.graph import EntityType, export_investigation
from olympus.argus.ip_osint import (
    IpParseError,
    IpWhoisClient,
    export_ip_intel,
)
from olympus.argus.ip_scope import (
    IpOutOfScopeError,
    IpScopeError,
)
from olympus.argus.mac import (
    MacParseError,
    export_mac_intel,
)
from olympus.argus.mac_scope import MacOutOfScopeError, MacScopeError
from olympus.argus.myip import MyIpError, export_myip
from olympus.argus.phone import (
    PhoneParseError,
    export_phone_intel,
)
from olympus.argus.phone_scope import (
    PhoneOutOfScopeError,
    PhoneScopeError,
)
from olympus.argus.pipeline import BUILTIN_MODULES, EventPipeline, export_pipeline, load_preset
from olympus.argus.resolver import DnspythonResolver
from olympus.argus.scope import OutOfScopeError, ScopeError
from olympus.argus.web import (
    WebReconError,
    export_web_intel,
)
from olympus.argus.whois import (
    WhoisError,
    build_whois_asset,
    export_whois_report,
)
from olympus.core.fileio import atomic_write_text
from olympus.core.http import UrllibHttpClient
from olympus.core.paths import audit_log_path, output_path
from olympus.core.pinning import global_address_policy

app = typer.Typer(
    help="Argus — OSINT & passive recon.",
    no_args_is_help=True,
)

DEFAULT_FRONTING_OUTPUT = output_path("argus-fronting.json")
DEFAULT_INVESTIGATION_OUTPUT = output_path("argus-investigation.json")
DEFAULT_SCOPE_PATH = Path("examples/input/argus-scope.json")
DEFAULT_BLOCK_LOG_PATH = audit_log_path("argus-blocked.log")
DEFAULT_ASSETS_PATH = output_path("argus-assets.json")

DEFAULT_PHONE_SCOPE_PATH = Path("examples/input/argus-phone-scope.json")
DEFAULT_PHONE_BLOCK_LOG_PATH = audit_log_path("argus-phone-blocked.log")

DEFAULT_SITES_PATH = Path("examples/input/argus-sites.json")
DEFAULT_ACCOUNT_SCOPE_PATH = Path("examples/input/argus-accounts-scope.json")
DEFAULT_ACCOUNT_BLOCK_LOG_PATH = audit_log_path("argus-accounts-blocked.log")

DEFAULT_IP_SCOPE_PATH = Path("examples/input/argus-ip-scope.json")
DEFAULT_IP_BLOCK_LOG_PATH = audit_log_path("argus-ip-blocked.log")

DEFAULT_MAC_SCOPE_PATH = Path("examples/input/argus-mac-scope.json")
DEFAULT_MAC_BLOCK_LOG_PATH = audit_log_path("argus-mac-blocked.log")

_IP_DISCLAIMER = (
    "AUTHORIZED USE ONLY — --geo queries a third-party geolocation service about the target "
    "IP. Run it only with documented authorization. Re-run with --i-am-authorized to confirm."
)

_METADATA_DISCLAIMER = (
    "AUTHORIZED USE ONLY — extracting public profile metadata (avatar/bio/followers) about a "
    "real person is privacy-sensitive OSINT. Run it only with documented authorization/consent. "
    "Re-run with --i-am-authorized to confirm."
)

# Shown before any real, third-party lookup against a live number.
_AUTH_DISCLAIMER = (
    "AUTHORIZED USE ONLY — phone enrichment, breach and messaging lookups query real "
    "third-party services about a real person's number. Run them only with documented "
    "authorization/consent (pentest engagement, your own number, or study on numbers you "
    "control). Re-run with --i-am-authorized to confirm."
)


@app.command()
def scan(
    domain: str = typer.Option(..., "--domain", help="Domain to run passive DNS recon against."),
    scope: Path = typer.Option(
        DEFAULT_SCOPE_PATH,
        "--scope",
        help="Path to the JSON scope file listing authorized domains.",
    ),
    log: Path = typer.Option(
        DEFAULT_BLOCK_LOG_PATH,
        "--log",
        help="Path to the out-of-scope audit log.",
    ),
    output: Path = typer.Option(
        DEFAULT_ASSETS_PATH,
        "--output",
        help="Path for the core.Asset-compatible JSON export.",
    ),
) -> None:
    """Run passive DNS/MX/SPF/DMARC recon against a single in-scope domain."""
    try:
        result = DomainScanService(DnspythonResolver(), CrtShClient()).run(
            DomainScanRequest(domain=domain, scope_path=scope, audit_log_path=log)
        )
    except ScopeError as exc:
        typer.echo(f"argus: scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except OutOfScopeError as exc:
        typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc

    except CertificateTransparencyError as exc:
        typer.echo(f"argus: Certificate Transparency error: {exc}", err=True)
        raise typer.Exit(code=4) from exc
    export_assets(recon_to_assets(result), output)
    typer.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True))


@app.command()
def fronting(
    domain: str = typer.Option(..., "--domain", help="Domain to assess for CDN/WAF fronting."),
    scope: Path = typer.Option(
        DEFAULT_SCOPE_PATH, "--scope", help="JSON scope file listing authorized domains."
    ),
    log: Path = typer.Option(
        DEFAULT_BLOCK_LOG_PATH, "--log", help="Path to the out-of-scope audit log."
    ),
    asset_id: str = typer.Option(
        "AST-ARGUS-FRONT-1", "--asset-id", help="core.Asset id to attach findings to."
    ),
    output: Path = typer.Option(
        DEFAULT_FRONTING_OUTPUT, "--output", help="Fronting report JSON."
    ),
) -> None:
    """Passively check whether an in-scope domain is CDN/WAF-fronted and leaks its origin IP."""
    try:
        report = FrontingAssessmentService(DnspythonResolver(), CrtShClient()).run(
            FrontingAssessmentRequest(domain=domain, scope_path=scope, audit_log_path=log)
        )
    except ScopeError as exc:
        typer.echo(f"argus: scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except OutOfScopeError as exc:
        typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc

    except CertificateTransparencyError as exc:
        typer.echo(f"argus: Certificate Transparency error: {exc}", err=True)
        raise typer.Exit(code=4) from exc

    asset = report_to_asset(report, asset_id)
    findings = report_to_findings(report, asset_id)
    export_fronting(report, asset, findings, output)
    typer.echo(
        f"argus: {domain} — fronted={report.fronted} "
        f"({', '.join(report.providers) or 'no CDN'}); "
        f"{len(report.origin_leaks)} candidate origin leak(s); {output}"
    )
    if report.origin_leaks:
        raise typer.Exit(code=1)


@app.command("diff")
def diff_command(before: Path, after: Path) -> None:
    """Compare two Argus asset snapshots without performing network activity."""
    try:
        result = SnapshotDiffService().run(before, after)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        typer.echo(f"argus: diff error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(json.dumps(result.__dict__, indent=2, sort_keys=True))


def _read_targets(path: Path) -> list[str]:
    """Read one target per line, skipping blanks and ``#`` comments."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


@app.command()
def phone(
    number: str | None = typer.Option(
        None, "--number", help="E.164 (e.g. +14155550123) or national with --region."
    ),
    input_file: Path | None = typer.Option(
        None, "--input", help="File with one number per line (batch mode)."
    ),
    region: str | None = typer.Option(
        None, "--region", help="ISO region (e.g. US, IT) for national-format numbers."
    ),
    scope: Path = typer.Option(
        DEFAULT_PHONE_SCOPE_PATH, "--scope", help="JSON scope file of authorized E.164 prefixes."
    ),
    log: Path = typer.Option(DEFAULT_PHONE_BLOCK_LOG_PATH, "--log", help="Out-of-scope audit log."),
    enrich: bool = typer.Option(
        False, "--enrich", help="Carrier/line-type via Numverify (needs OLYMPUS_NUMVERIFY_KEY)."
    ),
    breach: bool = typer.Option(
        False, "--breach", help="Breach-intelligence exposure lookup (keyless third-party API)."
    ),
    messaging: bool = typer.Option(
        False, "--messaging", help="Messaging-platform presence (needs OLYMPUS_RAPIDAPI_KEY)."
    ),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm documented authorization for real lookups."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="If set, export the phone-intel bundle(s) as JSON to this path."
    ),
) -> None:
    """Profile in-scope phone number(s): offline parsing + opt-in real lookups.

    Provide exactly one of --number (single) or --input (batch, one per line).
    """
    if (number is None) == (input_file is None):
        typer.echo("argus: provide exactly one of --number or --input", err=True)
        raise typer.Exit(code=2)

    http = UrllibHttpClient.from_config()
    service = PhoneProfileService(
        carrier_client=NumverifyClient.from_env(http) if enrich else None,
        breach_client=HudsonRockBreachClient(http) if breach else None,
        messaging_client=RapidApiMessagingClient.from_env(http) if messaging else None,
    )

    def request_for(target: str) -> PhoneProfileRequest:
        return PhoneProfileRequest(
            number=target,
            region=region,
            scope_path=scope,
            audit_log_path=log,
            enrich=enrich,
            breach=breach,
            messaging=messaging,
            authorized=i_am_authorized,
        )

    try:
        if number is not None:
            outcome = service.run(request_for(number))
            for warning in outcome.warnings:
                typer.echo(f"argus: warning: {warning}", err=True)
            typer.echo(json.dumps(outcome.intel.to_dict(), indent=2, sort_keys=True))
            if output is not None:
                export_phone_intel(outcome.intel, output)
                typer.echo(f"argus: wrote phone intel to {output}", err=True)
            return

        assert input_file is not None  # noqa: S101 (guaranteed by exactly-one check)
        batch = service.run_many(tuple(request_for(target) for target in _read_targets(input_file)))
    except AuthorizationRequiredError as exc:
        typer.echo(f"argus: {_AUTH_DISCLAIMER}", err=True)
        raise typer.Exit(code=4) from exc
    except PhoneParseError as exc:
        typer.echo(f"argus: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except PhoneScopeError as exc:
        typer.echo(f"argus: phone scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except PhoneOutOfScopeError as exc:
        typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc
    except OSError as exc:
        typer.echo(f"argus: could not read phone input: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    for warning in batch.warnings:
        typer.echo(f"argus: {warning}", err=True)
    payload = [intel.to_dict() for intel in batch.intels]
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    if output is not None:
        atomic_write_text(
            output, json.dumps(payload, indent=2, sort_keys=True), mode=0o600
        )
    typer.echo(f"argus: profiled {len(batch.intels)} number(s)", err=True)


@app.command()
def accounts(
    username: str | None = typer.Option(
        None, "--username", help="Handle to enumerate across sites."
    ),
    input_file: Path | None = typer.Option(
        None, "--input", help="File with one handle per line (batch mode)."
    ),
    scope: Path = typer.Option(
        DEFAULT_ACCOUNT_SCOPE_PATH, "--scope", help="JSON allowlist of authorized handles."
    ),
    log: Path = typer.Option(
        DEFAULT_ACCOUNT_BLOCK_LOG_PATH, "--log", help="Out-of-scope audit log."
    ),
    sites: Path = typer.Option(DEFAULT_SITES_PATH, "--sites", help="JSON site registry to check."),
    metadata: bool = typer.Option(
        False, "--metadata", help="Also extract public profile metadata (needs --i-am-authorized)."
    ),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm documented authorization for metadata scraping."
    ),
    concurrency: int = typer.Option(
        8, "--concurrency", min=1, max=64, help="Parallel site checks per handle."
    ),
    rate: float = typer.Option(
        0.0, "--rate", min=0.0, help="Minimum seconds between requests (politeness rate limit)."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="If set, export the account-intel bundle(s) as JSON to this path."
    ),
) -> None:
    """Enumerate in-scope handle(s) across a curated list of public sites.

    Provide exactly one of --username (single) or --input (batch, one per line).
    """
    if (username is None) == (input_file is None):
        typer.echo("argus: provide exactly one of --username or --input", err=True)
        raise typer.Exit(code=2)

    try:
        specs = load_site_registry(sites)
        client = UrllibHttpClient.from_config(
            min_interval=rate if rate > 0.0 else None,
            redirect_validator=validate_public_site_url,
            address_policy=global_address_policy(),
        )
        service = AccountEnumerationService(tuple(specs), client)

        def request_for(handle: str) -> AccountEnumerationRequest:
            return AccountEnumerationRequest(
                handle=handle,
                scope_path=scope,
                audit_log_path=log,
                metadata=metadata,
                authorized=i_am_authorized,
                concurrency=concurrency,
            )

        intels: tuple[AccountIntel, ...]
        if username is not None:
            outcome = service.run(request_for(username))
            intels = (outcome.intel,)
        else:
            assert input_file is not None  # noqa: S101 (guaranteed by exactly-one check)
            batch = service.run_many(
                tuple(request_for(handle) for handle in _read_targets(input_file))
            )
            intels = batch.intels
            for warning in batch.warnings:
                typer.echo(f"argus: {warning}", err=True)
    except AuthorizationRequiredError as exc:
        typer.echo(f"argus: {_METADATA_DISCLAIMER}", err=True)
        raise typer.Exit(code=4) from exc
    except (SiteRegistryError, ValueError) as exc:
        typer.echo(f"argus: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except AccountScopeError as exc:
        typer.echo(f"argus: account scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except AccountOutOfScopeError as exc:
        typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc
    except OSError as exc:
        typer.echo(f"argus: could not read account input: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    for intel in intels:
        typer.echo(
            f"argus: '{intel.result.handle}' found on "
            f"{len(intel.result.existing())}/{len(specs)} site(s)",
            err=True,
        )

    if username is not None:
        payload: object = intels[0].to_dict() if intels else {}
    else:
        payload = [intel.to_dict() for intel in intels]
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    if output is not None:
        atomic_write_text(
            output, json.dumps(payload, indent=2, sort_keys=True), mode=0o600
        )
        typer.echo(f"argus: wrote account intel to {output}", err=True)


@app.command()
def ip(
    ip_address: str | None = typer.Option(None, "--ip", help="IPv4/IPv6 address to profile."),
    input_file: Path | None = typer.Option(
        None, "--input", help="File with one IP per line (batch mode)."
    ),
    scope: Path = typer.Option(
        DEFAULT_IP_SCOPE_PATH, "--scope", help="JSON scope file of authorized CIDR networks."
    ),
    log: Path = typer.Option(DEFAULT_IP_BLOCK_LOG_PATH, "--log", help="Out-of-scope audit log."),
    geo: bool = typer.Option(
        False, "--geo", help="Geolocation/ASN via encrypted ipwho.is (third-party, keyless)."
    ),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm authorization for the third-party geo lookup."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="If set, export the IP-intel bundle(s) as JSON to this path."
    ),
) -> None:
    """Profile in-scope IP address(es): offline classification + opt-in geolocation.

    Provide exactly one of --ip (single) or --input (batch, one per line).
    """
    if (ip_address is None) == (input_file is None):
        typer.echo("argus: provide exactly one of --ip or --input", err=True)
        raise typer.Exit(code=2)
    http = UrllibHttpClient.from_config()
    service = IpProfileService(IpWhoisClient(http) if geo else None)

    def request_for(target: str) -> IpProfileRequest:
        return IpProfileRequest(
            ip_address=target,
            scope_path=scope,
            audit_log_path=log,
            geolocate=geo,
            authorized=i_am_authorized,
        )

    try:
        if ip_address is not None:
            outcome = service.run(request_for(ip_address))
            for warning in outcome.warnings:
                typer.echo(f"argus: warning: {warning}", err=True)
            typer.echo(json.dumps(outcome.intel.to_dict(), indent=2, sort_keys=True))
            if output is not None:
                export_ip_intel(outcome.intel, output)
                typer.echo(f"argus: wrote IP intel to {output}", err=True)
            return

        assert input_file is not None  # noqa: S101 (guaranteed by exactly-one check)
        batch = service.run_many(tuple(request_for(target) for target in _read_targets(input_file)))
    except AuthorizationRequiredError as exc:
        typer.echo(f"argus: {_IP_DISCLAIMER}", err=True)
        raise typer.Exit(code=4) from exc
    except IpParseError as exc:
        typer.echo(f"argus: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except IpScopeError as exc:
        typer.echo(f"argus: IP scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except IpOutOfScopeError as exc:
        typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc
    except OSError as exc:
        typer.echo(f"argus: could not read IP input: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    for warning in batch.warnings:
        typer.echo(f"argus: {warning}", err=True)
    payload = [intel.to_dict() for intel in batch.intels]
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    if output is not None:
        atomic_write_text(
            output, json.dumps(payload, indent=2, sort_keys=True), mode=0o600
        )
    typer.echo(f"argus: profiled {len(batch.intels)} IP(s)", err=True)


_INVESTIGATE_DISCLAIMER = (
    "AUTHORIZED USE ONLY — an investigation fans out third-party OSINT lookups about the seed "
    "and everything it links to. Run it only with documented authorization. Re-run with "
    "--i-am-authorized to confirm."
)
DEFAULT_INVESTIGATION_LOG = audit_log_path("argus-investigate.log")


@app.command()
def investigate(
    seed_type: EntityType = typer.Option(
        ..., "--seed-type", help="Seed entity type (domain/host/ip/email/phone/username)."
    ),
    seed_value: str = typer.Option(..., "--seed-value", help="Seed entity value."),
    name: str = typer.Option("investigation", "--name", help="Investigation name."),
    depth: int = typer.Option(1, "--depth", min=0, max=3, help="How many pivot hops to expand."),
    sites: Path = typer.Option(
        DEFAULT_SITES_PATH, "--sites", help="Site registry for username transforms."
    ),
    domain_scope: Path = typer.Option(
        DEFAULT_SCOPE_PATH,
        "--domain-scope",
        help="JSON scope for domain/host DNS and Certificate Transparency pivots.",
    ),
    ip_scope: Path = typer.Option(
        DEFAULT_IP_SCOPE_PATH,
        "--ip-scope",
        help="JSON CIDR scope for optional IP geolocation pivots.",
    ),
    account_scope: Path = typer.Option(
        DEFAULT_ACCOUNT_SCOPE_PATH,
        "--account-scope",
        help="JSON handle scope for public-account pivots.",
    ),
    geo: bool = typer.Option(False, "--geo", help="Enable IP geolocation/ASN (third-party)."),
    log: Path = typer.Option(DEFAULT_INVESTIGATION_LOG, "--log", help="Investigation audit log."),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm documented authorization for the fan-out."
    ),
    output: Path = typer.Option(
        DEFAULT_INVESTIGATION_OUTPUT, "--output", help="Graph JSON output."
    ),
    mermaid: Path | None = typer.Option(
        None, "--mermaid", help="If set, also write a Mermaid diagram of the graph."
    ),
    dot: Path | None = typer.Option(None, "--dot", help="If set, also write a Graphviz DOT graph."),
    graphml: Path | None = typer.Option(
        None, "--graphml", help="If set, also write a GraphML graph (Gephi/Neo4j/yEd)."
    ),
) -> None:
    """Build an OSINT investigation graph by pivoting from a seed entity (flowsint-style)."""
    try:
        site_specs = load_site_registry(sites)
        service = InvestigationService(
            resolver=DnspythonResolver(),
            ct_client=CrtShClient(),
            http=UrllibHttpClient.from_config(
                redirect_validator=validate_public_site_url,
                address_policy=global_address_policy(),
            ),
            site_specs=tuple(site_specs),
        )
        outcome = service.run(
            InvestigationRequest(
                name=name,
                seed_type=seed_type,
                seed_value=seed_value,
                depth=depth,
                domain_scope_path=domain_scope,
                ip_scope_path=ip_scope,
                account_scope_path=account_scope,
                audit_log_path=log,
                geolocate=geo,
                authorized=i_am_authorized,
            )
        )
    except AuthorizationRequiredError as exc:
        typer.echo(f"argus: {_INVESTIGATE_DISCLAIMER}", err=True)
        raise typer.Exit(code=4) from exc
    except (SiteRegistryError, ScopeError, IpScopeError, AccountScopeError, ValueError) as exc:
        typer.echo(f"argus: investigation configuration error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except (OutOfScopeError, IpOutOfScopeError, AccountOutOfScopeError) as exc:
        typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc
    except OSError as exc:
        typer.echo(f"argus: investigation I/O failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    graph = outcome.graph
    for warning in outcome.warnings:
        typer.echo(f"argus: {warning}", err=True)

    typer.echo(json.dumps(graph.to_dict(), indent=2, sort_keys=True))
    export_investigation(graph, output)
    for target, renderer in (
        (mermaid, graph.to_mermaid),
        (dot, graph.to_dot),
        (graphml, graph.to_graphml),
    ):
        if target is not None:
            atomic_write_text(target, renderer(), mode=0o600)
    typer.echo(
        f"argus: investigation '{name}' — {len(graph.entities)} entit(y/ies), "
        f"{len(graph.relationships)} edge(s); {output}",
        err=True,
    )


DEFAULT_EMAIL_OUTPUT = output_path("argus-email.json")
DEFAULT_WEB_OUTPUT = output_path("argus-web.json")
DEFAULT_DNS_OUTPUT = output_path("argus-dns.json")
DEFAULT_WHOIS_OUTPUT = output_path("argus-whois.json")

_EMAIL_DISCLAIMER = (
    "AUTHORIZED USE ONLY — --enrich runs passive live lookups (MX resolution and Gravatar "
    "presence) about a real person's address. Run it only with documented authorization or "
    "consent. Re-run with --i-am-authorized to confirm."
)

_MAC_DISCLAIMER = (
    "AUTHORIZED USE ONLY — --vendor sends the target's OUI to macvendors.com. "
    "Run it only within a documented engagement. Re-run with --i-am-authorized "
    "and an OUI scope file to confirm."
)


@app.command()
def email(
    address: str = typer.Option(..., "--email", help="Email address to analyze."),
    enrich: bool = typer.Option(
        False, "--enrich", help="Run passive live MX + Gravatar checks (network, opt-in)."
    ),
    scope: Path = typer.Option(
        DEFAULT_SCOPE_PATH, "--scope", help="JSON scope file (domain must be in scope to enrich)."
    ),
    log: Path = typer.Option(
        DEFAULT_BLOCK_LOG_PATH, "--log", help="Path to the out-of-scope audit log."
    ),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm authorization for the live enrichment."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="If set, export the email-intel bundle as JSON to this path."
    ),
) -> None:
    """Analyze an email address offline; optionally run passive live enrichment."""
    try:
        intel = EmailAnalysisService(DnspythonResolver(), UrllibHttpClient.from_config()).run(
            EmailAnalysisRequest(
                address=address,
                enrich=enrich,
                authorized=i_am_authorized,
                scope_path=scope,
                audit_log_path=log,
            )
        )
    except EmailParseError as exc:
        typer.echo(f"argus: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except AuthorizationRequiredError as exc:
        typer.echo(f"argus: {_EMAIL_DISCLAIMER}", err=True)
        raise typer.Exit(code=4) from exc
    except ScopeError as exc:
        typer.echo(f"argus: scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except OutOfScopeError as exc:
        typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc
    typer.echo(json.dumps(intel.to_dict(), indent=2, sort_keys=True))
    if output is not None:
        export_email_intel(intel, output)
        typer.echo(f"argus: wrote email intel to {output}", err=True)


@app.command()
def mac(
    address: str = typer.Option(..., "--mac", help="MAC address to classify."),
    vendor: bool = typer.Option(
        False, "--vendor", help="Resolve the OUI to a vendor via macvendors.com (network)."
    ),
    scope: Path = typer.Option(
        DEFAULT_MAC_SCOPE_PATH,
        "--scope",
        help="JSON scope file whose OUI allowlist authorizes the vendor lookup.",
    ),
    log: Path = typer.Option(
        DEFAULT_MAC_BLOCK_LOG_PATH,
        "--log",
        help="Path to the out-of-scope MAC audit log.",
    ),
    i_am_authorized: bool = typer.Option(
        False,
        "--i-am-authorized",
        help="Confirm documented authorization for the live vendor lookup.",
    ),
    output: Path | None = typer.Option(
        None, "--output", help="If set, export the MAC-intel bundle as JSON to this path."
    ),
) -> None:
    """Classify a MAC address offline; optionally resolve its vendor from the OUI registry."""
    try:
        intel = MacAnalysisService(UrllibHttpClient.from_config()).run(
            MacAnalysisRequest(
                address=address,
                vendor=vendor,
                authorized=i_am_authorized,
                scope_path=scope,
                audit_log_path=log,
            )
        )
    except MacParseError as exc:
        typer.echo(f"argus: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except MacScopeError as exc:
        typer.echo(f"argus: scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except MacOutOfScopeError as exc:
        typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc
    except AuthorizationRequiredError as exc:
        typer.echo(f"argus: {_MAC_DISCLAIMER}", err=True)
        raise typer.Exit(code=4) from exc
    typer.echo(json.dumps(intel.to_dict(), indent=2, sort_keys=True))
    if output is not None:
        export_mac_intel(intel, output)
        typer.echo(f"argus: wrote MAC intel to {output}", err=True)


@app.command()
def myip(
    geo: bool = typer.Option(
        False, "--geo", help="Classify and geolocate the discovered public IP (network)."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="If set, export the result as JSON to this path."
    ),
) -> None:
    """Discover this machine's own public IP address (and optionally geolocate it)."""
    try:
        http = UrllibHttpClient.from_config()
        result = MyIpDiscoveryService(http, http).run(MyIpDiscoveryRequest(geolocate=geo))
    except MyIpError as exc:
        typer.echo(f"argus: {exc}", err=True)
        raise typer.Exit(code=4) from exc
    typer.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    if output is not None:
        export_myip(result, output)
        typer.echo(f"argus: wrote myip result to {output}", err=True)


@app.command()
def web(
    url: str = typer.Option(..., "--url", help="Target URL or host for passive HTTP recon."),
    scope: Path = typer.Option(
        DEFAULT_SCOPE_PATH, "--scope", help="JSON scope file listing authorized domains."
    ),
    log: Path = typer.Option(
        DEFAULT_BLOCK_LOG_PATH, "--log", help="Path to the out-of-scope audit log."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="If set, export the web-intel bundle as JSON to this path."
    ),
) -> None:
    """Fetch an in-scope URL once and report its passive HTTP security posture."""
    try:
        http = UrllibHttpClient.from_config(
            redirect_validator=lambda redirect_url: authorize_web_url(redirect_url, scope, log),
            # Pin the socket to the address the scope check just approved, so a
            # rebound DNS answer cannot redirect the fetch after validation.
            address_policy=web_address_policy(scope, log),
        )
        intel = WebReconService(http).run(
            WebReconRequest(url=url, scope_path=scope, audit_log_path=log)
        )
    except InvalidWebTargetError as exc:
        typer.echo(f"argus: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except ScopeError as exc:
        typer.echo(f"argus: scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except OutOfScopeError as exc:
        typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc

    except WebReconError as exc:
        typer.echo(f"argus: {exc}", err=True)
        raise typer.Exit(code=4) from exc

    typer.echo(json.dumps(intel.to_dict(), indent=2, sort_keys=True))
    if output is not None:
        export_web_intel(intel, output)
        typer.echo(f"argus: wrote web intel to {output}", err=True)
    if intel.findings:
        raise typer.Exit(code=1)


@app.command()
def dns(
    domain: str = typer.Option(..., "--domain", help="Domain to enumerate DNS records for."),
    types: str | None = typer.Option(
        None, "--types", help="Comma-separated record types (default: A,AAAA,MX,TXT,NS,CNAME,SOA)."
    ),
    scope: Path = typer.Option(
        DEFAULT_SCOPE_PATH, "--scope", help="JSON scope file listing authorized domains."
    ),
    log: Path = typer.Option(
        DEFAULT_BLOCK_LOG_PATH, "--log", help="Path to the out-of-scope audit log."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="If set, export the DNS report as JSON to this path."
    ),
) -> None:
    """Enumerate DNS records for an in-scope domain over DNS-over-HTTPS."""
    record_types = tuple(t.strip() for t in types.split(",") if t.strip()) if types else None
    try:
        report = DnsLookupService(UrllibHttpClient.from_config()).run(
            DnsLookupRequest(
                domain=domain,
                scope_path=scope,
                audit_log_path=log,
                record_types=record_types or RECORD_TYPES,
            )
        )
    except ScopeError as exc:
        typer.echo(f"argus: scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except OutOfScopeError as exc:
        typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc

    except DnsRecordError as exc:
        typer.echo(f"argus: {exc}", err=True)
        raise typer.Exit(code=4) from exc

    asset = build_dns_asset(report)
    payload = {"report": report.to_dict(), "asset": json.loads(asset.model_dump_json())}
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    if output is not None:
        export_dns_report(report, asset, output)
        typer.echo(f"argus: wrote DNS report to {output}", err=True)


@app.command()
def whois(
    domain: str = typer.Option(..., "--domain", help="Domain to query registration data for."),
    scope: Path = typer.Option(
        DEFAULT_SCOPE_PATH, "--scope", help="JSON scope file listing authorized domains."
    ),
    log: Path = typer.Option(
        DEFAULT_BLOCK_LOG_PATH, "--log", help="Path to the out-of-scope audit log."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="If set, export the WHOIS report as JSON to this path."
    ),
) -> None:
    """Query registration data (registrar, dates, name servers) for an in-scope domain via RDAP."""
    try:
        report = WhoisLookupService(UrllibHttpClient.from_config()).run(
            WhoisLookupRequest(domain=domain, scope_path=scope, audit_log_path=log)
        )
    except ScopeError as exc:
        typer.echo(f"argus: scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except OutOfScopeError as exc:
        typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc

    except WhoisError as exc:
        typer.echo(f"argus: {exc}", err=True)
        raise typer.Exit(code=4) from exc

    asset = build_whois_asset(report)
    payload = {"report": report.to_dict(), "asset": json.loads(asset.model_dump_json())}
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    if output is not None:
        export_whois_report(report, asset, output)
        typer.echo(f"argus: wrote WHOIS report to {output}", err=True)


@app.command()
def doctor() -> None:
    """Diagnose Argus: required libraries and optional enrichment API keys."""
    report = ArgusDiagnosticsService().run()
    typer.echo(json.dumps(report.to_dict(), indent=2, sort_keys=True))


@app.command("pipeline")
def pipeline_command(
    preset: Path = typer.Option(..., "--preset", help="Versioned Argus pipeline preset JSON."),
    output: Path | None = typer.Option(None, "--output", help="Owner-only result JSON path."),
    audit: Path | None = typer.Option(None, "--audit", help="Owner-only structured audit path."),
) -> None:
    """Run the bounded offline event/preset reconnaissance pipeline."""
    try:
        configuration = load_preset(preset)
        document = EventPipeline(BUILTIN_MODULES).run(configuration, audit_path=audit)
    except (ValueError, OSError) as exc:
        typer.echo(f"argus: pipeline error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    payload = document.model_dump_json(indent=2)
    if output is None:
        typer.echo(payload)
    else:
        export_pipeline(document, output)
        typer.echo(f"argus: wrote pipeline result to {output}", err=True)
