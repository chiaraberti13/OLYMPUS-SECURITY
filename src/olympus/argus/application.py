"""Application use cases for Argus.

This layer coordinates authorization and passive-recon domain services without
depending on Typer, console output, or concrete network clients.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from olympus.argus.accounts import (
    AccountIntel,
    SiteSpec,
    build_account_assets,
    build_account_finding,
    enumerate_accounts,
)
from olympus.argus.accounts_scope import AccountOutOfScopeError, enforce_account_scope
from olympus.argus.ct import CertificateTransparencyClient
from olympus.argus.diff import AssetDiff, diff_snapshots
from olympus.argus.dns_records import RECORD_TYPES, DnsRecordReport, resolve_records
from olympus.argus.email_osint import (
    EmailIntel,
    analyze_email,
    build_email_asset,
    build_email_findings,
    enrich_email,
)
from olympus.argus.enrichment import (
    EnrichmentError,
    MessagingPresence,
    MessagingPresenceClient,
    PhoneEnrichment,
    PhoneEnrichmentClient,
)
from olympus.argus.fronting import FrontingReport, assess_fronting
from olympus.argus.graph import Entity, EntityType, Investigation
from olympus.argus.ip_osint import (
    IpGeo,
    IpGeoClient,
    IpGeoError,
    IpIntel,
    IpParseError,
    analyze_ip,
    build_ip_asset,
    build_ip_findings,
)
from olympus.argus.ip_scope import IpOutOfScopeError, enforce_ip_scope
from olympus.argus.mac import (
    MacIntel,
    analyze_mac,
    build_mac_asset,
    build_mac_findings,
    lookup_vendor,
)
from olympus.argus.mac_scope import enforce_mac_scope
from olympus.argus.myip import MyIpResult, build_result, discover_public_ip
from olympus.argus.phone import (
    PhoneIntel,
    PhoneParseError,
    analyze_phone,
    build_phone_asset,
    build_phone_findings,
)
from olympus.argus.phone_scope import PhoneOutOfScopeError, enforce_phone_scope
from olympus.argus.recon import DomainRecon, scan_domain
from olympus.argus.resolver import DnsResolver
from olympus.argus.scope import OutOfScopeError, enforce_scope
from olympus.argus.transforms import TransformContext, run_investigation
from olympus.argus.web import (
    WebIntel,
    WebReconError,
    build_web_asset,
    build_web_findings,
    fetch_web,
    host_of,
)
from olympus.argus.whois import WhoisReport, lookup_domain
from olympus.core.addresses import resolve_authorized_addresses
from olympus.core.execution import (
    AuthorizationRequiredError as CoreAuthorizationRequiredError,
)
from olympus.core.execution import ExecutionPolicy
from olympus.core.http import HttpClient
from olympus.core.pinning import AddressPolicy
from olympus.integrations.diagnostics import Report, check_env_set, check_python_module


class AuthorizationRequiredError(CoreAuthorizationRequiredError):
    """Argus compatibility subtype of the shared authorization error."""


def _require_authorization(authorized: bool, operation: str) -> None:
    """Apply the shared authorization policy before a privacy-sensitive adapter."""
    try:
        ExecutionPolicy(authorized=authorized).require_authorization(operation)
    except CoreAuthorizationRequiredError as exc:
        raise AuthorizationRequiredError(str(exc)) from exc


@dataclass(frozen=True)
class SnapshotDiffService:
    """Compare two versioned Argus snapshots without CLI or network dependencies."""

    def run(self, before: Path, after: Path) -> AssetDiff:
        """Validate both shared contracts before returning hostname-level changes."""
        return diff_snapshots(before, after)


@dataclass(frozen=True)
class ArgusDiagnosticsService:
    """Build a secret-safe, read-only report of the Argus runtime dependencies."""

    def run(self) -> Report:
        """Check required modules and optional credentials without reading secret values."""
        report = Report("argus doctor")
        for module in ("dns", "phonenumbers"):
            report.add(check_python_module(module, optional=False))
        for key in ("OLYMPUS_NUMVERIFY_KEY", "OLYMPUS_RAPIDAPI_KEY"):
            report.add(check_env_set(key, optional=True, secret=True))
        return report


@dataclass(frozen=True)
class InvestigationRequest:
    """Command-independent input and engagement perimeter for one graph expansion."""

    name: str
    seed_type: EntityType
    seed_value: str
    depth: int
    domain_scope_path: Path
    ip_scope_path: Path
    account_scope_path: Path
    audit_log_path: Path
    geolocate: bool = False
    authorized: bool = False


@dataclass(frozen=True)
class InvestigationOutcome:
    """Investigation graph plus explicit non-fatal pivot warnings."""

    graph: Investigation
    warnings: tuple[str, ...] = ()


@dataclass
class _InvestigationScopeGate:
    """Apply the correct scope dialect to every entity before a network pivot."""

    domain_scope_path: Path
    ip_scope_path: Path
    account_scope_path: Path
    audit_log_path: Path
    warnings: list[str] = field(default_factory=list)
    _allowed: set[str] = field(default_factory=set)
    _blocked: set[str] = field(default_factory=set)

    @staticmethod
    def _key(entity: Entity) -> str:
        return entity.id

    def require(self, entity: Entity) -> None:
        """Raise for an out-of-scope direct seed and cache successful decisions."""
        key = self._key(entity)
        if key in self._allowed:
            return
        if entity.entity_type in (EntityType.DOMAIN, EntityType.HOST):
            enforce_scope(entity.value, self.domain_scope_path, self.audit_log_path)
        elif entity.entity_type is EntityType.IP:
            enforce_ip_scope(entity.value, self.ip_scope_path, self.audit_log_path)
        elif entity.entity_type is EntityType.USERNAME:
            enforce_account_scope(entity.value, self.account_scope_path, self.audit_log_path)
        self._allowed.add(key)

    def allows(self, entity: Entity) -> bool:
        """Skip and audit out-of-scope discovered pivots without aborting the graph."""
        key = self._key(entity)
        if key in self._blocked:
            return False
        try:
            self.require(entity)
        except (OutOfScopeError, IpOutOfScopeError, AccountOutOfScopeError):
            self._blocked.add(key)
            self.warnings.append(
                f"skipping out-of-scope {entity.entity_type.value} pivot {entity.value!r} (logged)"
            )
            return False
        return True


@dataclass(frozen=True)
class InvestigationService:
    """Authorize, scope, audit, and execute bounded OSINT graph transforms."""

    resolver: DnsResolver
    ct_client: CertificateTransparencyClient
    http: HttpClient
    site_specs: tuple[SiteSpec, ...]

    @staticmethod
    def _seed_uses_network(request: InvestigationRequest) -> bool:
        if request.depth == 0:
            return False
        if request.seed_type in (EntityType.DOMAIN, EntityType.HOST, EntityType.USERNAME):
            return True
        return request.seed_type is EntityType.IP and request.geolocate

    @staticmethod
    def _log_start(request: InvestigationRequest) -> None:
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "investigation": request.name,
            "seed_type": request.seed_type.value,
            "seed_value": request.seed_value,
            "action": "investigation_started",
        }
        request.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        with request.audit_log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")

    def run(self, request: InvestigationRequest) -> InvestigationOutcome:
        """Refuse unauthorized fan-out and gate every direct or discovered network pivot."""
        _require_authorization(request.authorized, "OSINT investigation fan-out")
        if not request.name.strip():
            raise ValueError("investigation name must not be empty")
        if not request.seed_value.strip():
            raise ValueError("investigation seed value must not be empty")
        if not 0 <= request.depth <= 3:
            raise ValueError("investigation depth must be between 0 and 3")

        gate = _InvestigationScopeGate(
            request.domain_scope_path,
            request.ip_scope_path,
            request.account_scope_path,
            request.audit_log_path,
        )
        if self._seed_uses_network(request):
            gate.require(Entity(request.seed_type, request.seed_value))
        self._log_start(request)
        context = TransformContext(
            resolver=self.resolver,
            ct_client=self.ct_client,
            http=self.http,
            site_specs=list(self.site_specs),
            geolocate=request.geolocate,
            scope_guard=gate.allows,
            warnings=gate.warnings,
        )
        graph = run_investigation(
            request.name,
            request.seed_type,
            request.seed_value,
            context,
            depth=request.depth,
        )
        return InvestigationOutcome(graph=graph, warnings=tuple(context.warnings))


@dataclass(frozen=True)
class AccountEnumerationRequest:
    """Command-independent input for one scoped account enumeration."""

    handle: str
    scope_path: Path
    audit_log_path: Path
    metadata: bool = False
    authorized: bool = False
    concurrency: int = 8


@dataclass(frozen=True)
class AccountEnumerationOutcome:
    """One handle's complete presence/partial/error results."""

    intel: AccountIntel


@dataclass(frozen=True)
class AccountBatchEnumerationResult:
    """Batch account result with explicit out-of-scope skips."""

    intels: tuple[AccountIntel, ...]
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class AccountEnumerationService:
    """Authorize, scope, enumerate, and map account intelligence without Typer."""

    specs: tuple[SiteSpec, ...]
    http: HttpClient

    def run(self, request: AccountEnumerationRequest) -> AccountEnumerationOutcome:
        """Enforce policy before any configured site can receive the handle."""
        policy = ExecutionPolicy(
            authorized=request.authorized,
            max_concurrency=request.concurrency,
        )
        if request.metadata:
            try:
                policy.require_authorization("account metadata extraction")
            except CoreAuthorizationRequiredError as exc:
                raise AuthorizationRequiredError(str(exc)) from exc
        enforce_account_scope(request.handle, request.scope_path, request.audit_log_path)
        result = enumerate_accounts(
            request.handle,
            list(self.specs),
            self.http,
            want_metadata=request.metadata,
            concurrency=policy.max_concurrency,
        )
        assets = build_account_assets(result)
        finding = build_account_finding(assets[0].asset_id, result) if assets else None
        return AccountEnumerationOutcome(
            AccountIntel(result=result, assets=assets, findings=[finding] if finding else [])
        )

    def run_many(
        self, requests: tuple[AccountEnumerationRequest, ...]
    ) -> AccountBatchEnumerationResult:
        """Enumerate a batch while auditing and recording out-of-scope skips."""
        intels: list[AccountIntel] = []
        warnings: list[str] = []
        for request in requests:
            try:
                outcome = self.run(request)
            except AccountOutOfScopeError:
                warnings.append(f"skipping out-of-scope handle {request.handle!r} (logged)")
            else:
                intels.append(outcome.intel)
        return AccountBatchEnumerationResult(intels=tuple(intels), warnings=tuple(warnings))


@dataclass(frozen=True)
class DomainScanRequest:
    """Validated command-independent input for one scoped domain scan."""

    domain: str
    scope_path: Path
    audit_log_path: Path


@dataclass(frozen=True)
class DomainScanService:
    """Authorize and execute passive domain reconnaissance."""

    resolver: DnsResolver
    ct_client: CertificateTransparencyClient

    def run(self, request: DomainScanRequest) -> DomainRecon:
        """Enforce scope before invoking either network-capable dependency."""
        enforce_scope(request.domain, request.scope_path, request.audit_log_path)
        return scan_domain(request.domain, self.resolver, self.ct_client)


@dataclass(frozen=True)
class EmailAnalysisRequest:
    """Command-independent input for offline analysis and optional enrichment."""

    address: str
    enrich: bool = False
    authorized: bool = False
    scope_path: Path | None = None
    audit_log_path: Path | None = None


@dataclass(frozen=True)
class EmailAnalysisService:
    """Analyze email locally and safely coordinate opt-in network enrichment."""

    resolver: DnsResolver
    http: HttpClient

    def run(self, request: EmailAnalysisRequest) -> EmailIntel:
        """Build shared contracts, authorizing scope before network access."""
        report = analyze_email(request.address)
        enrichment = None
        if request.enrich:
            _require_authorization(request.authorized, "email enrichment")
            if request.scope_path is None or request.audit_log_path is None:
                raise ValueError("scope_path and audit_log_path are required for email enrichment")
            enforce_scope(report.domain, request.scope_path, request.audit_log_path)
            enrichment = enrich_email(report, self.resolver, self.http)
        asset = build_email_asset(report, enrichment)
        return EmailIntel(
            report=report,
            asset=asset,
            enrichment=enrichment,
            findings=build_email_findings(asset.asset_id, report, enrichment),
        )


@dataclass(frozen=True)
class MacAnalysisRequest:
    """Command-independent input for offline MAC analysis and OUI enrichment."""

    address: str
    vendor: bool = False
    authorized: bool = False
    scope_path: Path | None = None
    audit_log_path: Path | None = None


@dataclass(frozen=True)
class MacAnalysisService:
    """Analyze a MAC locally and safely coordinate opt-in vendor lookup."""

    http: HttpClient

    def run(self, request: MacAnalysisRequest) -> MacIntel:
        """Authorize OUI scope before sending it to the third-party registry."""
        report = analyze_mac(request.address)
        vendor_name = None
        if request.vendor:
            _require_authorization(request.authorized, "MAC vendor lookup")
            if request.scope_path is None or request.audit_log_path is None:
                raise ValueError("scope_path and audit_log_path are required for vendor lookup")
            enforce_mac_scope(report.mac, request.scope_path, request.audit_log_path)
            vendor_name = lookup_vendor(report, self.http)
        asset = build_mac_asset(report, vendor_name)
        return MacIntel(
            report=report,
            asset=asset,
            vendor=vendor_name,
            findings=build_mac_findings(asset.asset_id, report),
        )


@dataclass(frozen=True)
class MyIpDiscoveryRequest:
    """Command-independent options for public-IP discovery."""

    geolocate: bool = False


@dataclass(frozen=True)
class MyIpDiscoveryService:
    """Discover self egress and optionally enrich it through a separate port."""

    discovery_http: HttpClient
    geo_http: HttpClient

    def run(self, request: MyIpDiscoveryRequest) -> MyIpResult:
        """Keep provider and optional geolocation traffic independently injectable."""
        public_ip = discover_public_ip(self.discovery_http)
        return build_result(public_ip, self.geo_http if request.geolocate else None)


@dataclass(frozen=True)
class PhoneProfileRequest:
    """Command-independent input for one scoped phone profile."""

    number: str
    scope_path: Path
    audit_log_path: Path
    region: str | None = None
    enrich: bool = False
    breach: bool = False
    messaging: bool = False
    authorized: bool = False


@dataclass(frozen=True)
class PhoneProfileOutcome:
    """One phone profile plus non-fatal adapter availability warnings."""

    intel: PhoneIntel
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class PhoneBatchProfileResult:
    """Batch result with successful profiles and explicit skipped-target warnings."""

    intels: tuple[PhoneIntel, ...]
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class PhoneProfileService:
    """Authorize, scope, enrich, and map phone intelligence without Typer."""

    carrier_client: PhoneEnrichmentClient | None = None
    breach_client: PhoneEnrichmentClient | None = None
    messaging_client: MessagingPresenceClient | None = None

    @staticmethod
    def _require_authorization(request: PhoneProfileRequest) -> None:
        if request.enrich or request.breach or request.messaging:
            _require_authorization(request.authorized, "phone enrichment")

    def run(self, request: PhoneProfileRequest) -> PhoneProfileOutcome:
        """Profile one number, refusing unauthorized/out-of-scope network activity."""
        self._require_authorization(request)
        report = analyze_phone(request.number, request.region)
        enforce_phone_scope(
            report.e164 or request.number, request.scope_path, request.audit_log_path
        )

        warnings: list[str] = []
        carrier_result: PhoneEnrichment | None = None
        breach_result: PhoneEnrichment | None = None
        messaging_result: MessagingPresence | None = None
        if report.e164 is not None:
            if request.enrich:
                if self.carrier_client is None:
                    warnings.append("--enrich skipped (set OLYMPUS_NUMVERIFY_KEY to enable)")
                else:
                    try:
                        carrier_result = self.carrier_client.enrich(report.e164)
                    except EnrichmentError:
                        warnings.append("carrier enrichment failed (third-party service error)")
            if request.breach:
                if self.breach_client is None:
                    warnings.append("--breach skipped (breach adapter unavailable)")
                else:
                    try:
                        breach_result = self.breach_client.enrich(report.e164)
                    except EnrichmentError:
                        warnings.append("breach lookup failed (third-party service error)")
            if request.messaging:
                if self.messaging_client is None:
                    warnings.append("--messaging skipped (set OLYMPUS_RAPIDAPI_KEY to enable)")
                else:
                    try:
                        messaging_result = self.messaging_client.lookup(report.e164)
                    except EnrichmentError:
                        warnings.append("messaging lookup failed (third-party service error)")

        enrichment_result = self._merge_enrichment(carrier_result, breach_result)
        asset = build_phone_asset(report, enrichment_result, messaging_result)
        intel = PhoneIntel(
            report=report,
            asset=asset,
            enrichment=enrichment_result,
            messaging=messaging_result,
            findings=build_phone_findings(
                asset.asset_id, report, enrichment_result, messaging_result
            ),
        )
        return PhoneProfileOutcome(intel=intel, warnings=tuple(warnings))

    def run_many(self, requests: tuple[PhoneProfileRequest, ...]) -> PhoneBatchProfileResult:
        """Profile a batch, recording parse/scope skips while preserving fatal scope errors."""
        intels: list[PhoneIntel] = []
        warnings: list[str] = []
        for request in requests:
            try:
                outcome = self.run(request)
            except PhoneParseError:
                warnings.append(f"skipping unparseable number {request.number!r}")
            except PhoneOutOfScopeError:
                warnings.append(f"skipping out-of-scope number {request.number!r} (logged)")
            else:
                intels.append(outcome.intel)
                warnings.extend(outcome.warnings)
        return PhoneBatchProfileResult(intels=tuple(intels), warnings=tuple(warnings))

    @staticmethod
    def _merge_enrichment(
        carrier: PhoneEnrichment | None,
        breach: PhoneEnrichment | None,
    ) -> PhoneEnrichment | None:
        if carrier is None and breach is None:
            return None
        return PhoneEnrichment(
            carrier=carrier.carrier if carrier is not None else "",
            line_type=carrier.line_type if carrier is not None else "",
            breach_count=breach.breach_count if breach is not None else 0,
            breach_sources=breach.breach_sources if breach is not None else (),
        )


@dataclass(frozen=True)
class IpProfileRequest:
    """Command-independent input for one scoped IP profile."""

    ip_address: str
    scope_path: Path
    audit_log_path: Path
    geolocate: bool = False
    authorized: bool = False


@dataclass(frozen=True)
class IpProfileOutcome:
    """One IP profile plus explicit non-fatal adapter warnings."""

    intel: IpIntel
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class IpBatchProfileResult:
    """Batch IP result with successful profiles and skipped-target warnings."""

    intels: tuple[IpIntel, ...]
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class IpProfileService:
    """Classify, authorize, scope, and optionally geolocate IP addresses."""

    geo_client: IpGeoClient | None = None

    def run(self, request: IpProfileRequest) -> IpProfileOutcome:
        """Refuse unauthorized/out-of-scope geo traffic before the adapter call."""
        if request.geolocate:
            _require_authorization(request.authorized, "IP geolocation")
        report = analyze_ip(request.ip_address)
        enforce_ip_scope(report.ip, request.scope_path, request.audit_log_path)

        warnings: list[str] = []
        geo: IpGeo | None = None
        if request.geolocate:
            if self.geo_client is None:
                warnings.append("geolocation skipped (adapter unavailable)")
            else:
                try:
                    geo = self.geo_client.geolocate(report.ip)
                except IpGeoError:
                    warnings.append("geolocation failed (third-party service error)")
        asset = build_ip_asset(report, geo)
        intel = IpIntel(
            report=report,
            asset=asset,
            geo=geo,
            findings=build_ip_findings(asset.asset_id, report, geo),
        )
        return IpProfileOutcome(intel=intel, warnings=tuple(warnings))

    def run_many(self, requests: tuple[IpProfileRequest, ...]) -> IpBatchProfileResult:
        """Profile a batch while recording invalid and out-of-scope skips."""
        intels: list[IpIntel] = []
        warnings: list[str] = []
        for request in requests:
            try:
                outcome = self.run(request)
            except IpParseError:
                warnings.append(f"skipping invalid IP {request.ip_address!r}")
            except IpOutOfScopeError:
                warnings.append(f"skipping out-of-scope IP {request.ip_address!r} (logged)")
            else:
                intels.append(outcome.intel)
                warnings.extend(outcome.warnings)
        return IpBatchProfileResult(intels=tuple(intels), warnings=tuple(warnings))


@dataclass(frozen=True)
class FrontingAssessmentRequest:
    """Command-independent input for one scoped fronting assessment."""

    domain: str
    scope_path: Path
    audit_log_path: Path
    max_subdomains: int = 50


@dataclass(frozen=True)
class FrontingAssessmentService:
    """Authorize and coordinate passive CDN/WAF fronting assessment."""

    resolver: DnsResolver
    ct_client: CertificateTransparencyClient

    def run(self, request: FrontingAssessmentRequest) -> FrontingReport:
        """Validate policy and scope before invoking network-capable ports."""
        if request.max_subdomains < 0:
            raise ValueError("max_subdomains must be zero or greater")
        enforce_scope(request.domain, request.scope_path, request.audit_log_path)
        return assess_fronting(
            request.domain,
            self.resolver,
            self.ct_client,
            max_subdomains=request.max_subdomains,
        )


@dataclass(frozen=True)
class DnsLookupRequest:
    """Command-independent input for one scoped DNS record lookup."""

    domain: str
    scope_path: Path
    audit_log_path: Path
    record_types: tuple[str, ...] = RECORD_TYPES


@dataclass(frozen=True)
class DnsLookupService:
    """Authorize and execute DNS-over-HTTPS record enumeration."""

    http: HttpClient

    def run(self, request: DnsLookupRequest) -> DnsRecordReport:
        """Enforce scope before invoking the injected network transport."""
        if not request.record_types:
            raise ValueError("record_types must contain at least one DNS record type")
        record_types = tuple(record_type.strip().upper() for record_type in request.record_types)
        if any(not record_type for record_type in record_types):
            raise ValueError("record_types cannot contain empty values")
        enforce_scope(request.domain, request.scope_path, request.audit_log_path)
        return resolve_records(request.domain, self.http, record_types)


@dataclass(frozen=True)
class WhoisLookupRequest:
    """Command-independent input for one scoped RDAP lookup."""

    domain: str
    scope_path: Path
    audit_log_path: Path


@dataclass(frozen=True)
class WhoisLookupService:
    """Authorize and execute domain-registration intelligence via RDAP."""

    http: HttpClient

    def run(self, request: WhoisLookupRequest) -> WhoisReport:
        """Enforce scope before invoking the injected network transport."""
        enforce_scope(request.domain, request.scope_path, request.audit_log_path)
        return lookup_domain(request.domain, self.http)


class InvalidWebTargetError(ValueError):
    """Raised when a web target cannot be normalized to a scoped hostname."""


def authorize_web_url(url: str, scope_path: Path, audit_log_path: Path) -> None:
    """Validate and authorize a web URL, including redirect destinations."""
    try:
        host = host_of(url)
    except WebReconError as exc:
        raise InvalidWebTargetError(str(exc)) from exc
    enforce_scope(host, scope_path, audit_log_path)


def web_address_policy(scope_path: Path, audit_log_path: Path) -> AddressPolicy:
    """Return the connect-time policy for scoped Argus web fetches.

    The HTTP stack calls this just before opening the socket and connects to
    exactly the address it returns, so the scope check and the connection can
    no longer disagree (DNS rebinding). Redirect hops go through it again.
    """

    def policy(host: str) -> tuple[str, ...]:
        normalized = host.strip().lower().rstrip(".")
        enforce_scope(normalized, scope_path, audit_log_path)
        return resolve_authorized_addresses(normalized)

    return policy


@dataclass(frozen=True)
class WebReconRequest:
    """Command-independent input for one scoped passive HTTP assessment."""

    url: str
    scope_path: Path
    audit_log_path: Path


@dataclass(frozen=True)
class WebReconService:
    """Authorize, fetch, and map passive HTTP posture to shared contracts."""

    http: HttpClient

    def run(self, request: WebReconRequest) -> WebIntel:
        """Validate and authorize the host before invoking HTTP."""
        authorize_web_url(request.url, request.scope_path, request.audit_log_path)
        report = fetch_web(request.url, self.http)
        asset = build_web_asset(report)
        return WebIntel(
            report=report,
            asset=asset,
            findings=build_web_findings(asset.asset_id, report),
        )
