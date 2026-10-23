"""Tests for command-independent Argus application use cases."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from olympus.argus.accounts import SiteSpec
from olympus.argus.accounts_scope import AccountOutOfScopeError
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
)
from olympus.argus.enrichment import MessagingPresence, PhoneEnrichment
from olympus.argus.graph import EntityType
from olympus.argus.ip_osint import IpGeo
from olympus.argus.ip_scope import IpOutOfScopeError
from olympus.argus.mac_scope import MacOutOfScopeError
from olympus.argus.myip import PROVIDERS, MyIpError
from olympus.argus.phone_scope import PhoneOutOfScopeError
from olympus.argus.scope import OutOfScopeError
from olympus.core.http import HttpResponse

DOMAIN = "olympusdemocorp.example"


class RecordingResolver:
    """Offline resolver that records every requested DNS lookup."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def resolve(self, name: str, record_type: str) -> list[str]:
        self.calls.append((name, record_type))
        if name == DOMAIN and record_type == "A":
            return ["203.0.113.10"]
        return []


class RecordingCtClient:
    """Offline CT client that records its authorized invocations."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def discover(self, domain: str) -> list[str]:
        self.calls.append(domain)
        return [f"portal.{domain}"]


class RecordingHttpClient:
    """Offline HTTP port returning a deterministic DoH response."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        self.calls.append(url)
        return HttpResponse(status_code=200, body='{"Answer":[{"data":"203.0.113.20"}]}')


class RecordingRdapClient:
    """Offline HTTP port returning a deterministic RDAP response."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        self.calls.append(url)
        return HttpResponse(
            status_code=200,
            body=json.dumps({"ldhName": DOMAIN.upper(), "status": ["active"]}),
        )


class RecordingWebClient:
    """Offline HTTP port returning a response with one disclosed banner."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        self.calls.append(url)
        return HttpResponse(status_code=200, headers={"Server": "test-server"})


class RecordingMyIpClient:
    """Offline public-IP provider port with explicit call evidence."""

    def __init__(self, available: bool = True) -> None:
        self.available = available
        self.calls: list[str] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        self.calls.append(url)
        if not self.available:
            return HttpResponse(status_code=503, body="")
        return HttpResponse(status_code=200, body='{"ip":"203.0.113.7"}')


class RecordingGeoClient:
    """Offline geolocation port kept separate from discovery traffic."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        self.calls.append(url)
        return HttpResponse(
            status_code=200,
            body='{"status":"success","country":"Example","countryCode":"EX"}',
        )


class RecordingPhoneEnrichmentClient:
    """Offline carrier or breach port with exact call evidence."""

    def __init__(self, result: PhoneEnrichment) -> None:
        self.result = result
        self.calls: list[str] = []

    def enrich(self, e164: str) -> PhoneEnrichment:
        self.calls.append(e164)
        return self.result


class RecordingMessagingClient:
    """Offline messaging port with exact call evidence."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def lookup(self, e164: str) -> MessagingPresence:
        self.calls.append(e164)
        return MessagingPresence("test-messaging", registered=True, has_public_photo=True)


class RecordingIpGeoClient:
    """Offline IP geolocation port with exact call evidence."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def geolocate(self, ip: str) -> IpGeo:
        self.calls.append(ip)
        return IpGeo(country="Example", org="Example Network", asn="AS64500")


class RecordingAccountClient:
    """Offline account-site HTTP port with partial-result evidence."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        self.calls.append(url)
        status = 200 if "github.com" in url else 503
        return HttpResponse(status_code=status, body="<bio>example</bio>")


def _scope(path: Path) -> Path:
    path.write_text(
        json.dumps({"engagement": "test", "allowed_domains": [DOMAIN]}),
        encoding="utf-8",
    )
    return path


def _mac_scope(path: Path, oui: str = "00:1A:2B") -> Path:
    path.write_text(
        json.dumps({"engagement": "test", "allowed_ouis": [oui]}),
        encoding="utf-8",
    )
    return path


def _phone_scope(path: Path, prefix: str = "+1650555") -> Path:
    path.write_text(
        json.dumps({"engagement": "test", "allowed_prefixes": [prefix]}),
        encoding="utf-8",
    )
    return path


def _ip_scope(path: Path, network: str = "203.0.113.0/24") -> Path:
    path.write_text(
        json.dumps({"engagement": "test", "allowed_networks": [network]}),
        encoding="utf-8",
    )
    return path


def _account_scope(path: Path, handle: str = "olympus_demo") -> Path:
    path.write_text(
        json.dumps({"engagement": "test", "allowed_handles": [handle]}),
        encoding="utf-8",
    )
    return path


def _account_specs() -> tuple[SiteSpec, ...]:
    return (
        SiteSpec(
            name="GitHub",
            url_template="https://github.com/{username}",
            metadata_patterns={"bio": r"<bio>([^<]+)</bio>"},
        ),
        SiteSpec(name="Unavailable", url_template="https://example.com/u/{username}"),
    )


def _investigation_request(
    tmp_path: Path,
    *,
    seed_type: EntityType = EntityType.DOMAIN,
    seed_value: str = DOMAIN,
    depth: int = 1,
    geolocate: bool = False,
    authorized: bool = True,
    account_handle: str = "olympus_demo",
) -> InvestigationRequest:
    return InvestigationRequest(
        name="case",
        seed_type=seed_type,
        seed_value=seed_value,
        depth=depth,
        domain_scope_path=_scope(tmp_path / "domain-scope.json"),
        ip_scope_path=_ip_scope(tmp_path / "ip-scope.json"),
        account_scope_path=_account_scope(tmp_path / "account-scope.json", handle=account_handle),
        audit_log_path=tmp_path / "investigation.log",
        geolocate=geolocate,
        authorized=authorized,
    )


def _investigation_service(
    resolver: RecordingResolver,
    ct_client: RecordingCtClient,
    http: RecordingHttpClient | RecordingAccountClient,
) -> InvestigationService:
    return InvestigationService(resolver, ct_client, http, _account_specs())


def test_snapshot_diff_service_uses_versioned_contracts(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    payload = {"schema_name": "olympus.argus-assets", "schema_version": "1.0.0", "assets": []}
    before.write_text(json.dumps(payload), encoding="utf-8")
    after.write_text(json.dumps(payload), encoding="utf-8")

    result = SnapshotDiffService().run(before, after)

    assert result.added == []
    assert result.removed == []
    assert result.unchanged == []


def test_argus_diagnostics_never_exposes_secret_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OLYMPUS_NUMVERIFY_KEY", "do-not-print-this")

    payload = ArgusDiagnosticsService().run().to_dict()

    assert "do-not-print-this" not in json.dumps(payload)
    checks = payload["checks"]
    assert isinstance(checks, list)
    numverify = next(check for check in checks if check["name"] == "env:OLYMPUS_NUMVERIFY_KEY")
    assert numverify["detail"] == "set"


def test_investigation_requires_authorization_before_network(tmp_path: Path) -> None:
    resolver = RecordingResolver()
    ct_client = RecordingCtClient()
    http = RecordingHttpClient()

    with pytest.raises(AuthorizationRequiredError):
        _investigation_service(resolver, ct_client, http).run(
            _investigation_request(tmp_path, authorized=False)
        )

    assert resolver.calls == []
    assert ct_client.calls == []
    assert http.calls == []


def test_investigation_blocks_out_of_scope_seed_before_network(tmp_path: Path) -> None:
    resolver = RecordingResolver()
    ct_client = RecordingCtClient()
    http = RecordingHttpClient()

    with pytest.raises(OutOfScopeError):
        _investigation_service(resolver, ct_client, http).run(
            _investigation_request(tmp_path, seed_value="outside.example")
        )

    assert resolver.calls == []
    assert ct_client.calls == []
    assert http.calls == []
    assert "blocked_out_of_scope" in (tmp_path / "investigation.log").read_text(encoding="utf-8")


def test_investigation_runs_scoped_domain_pivots_and_audits_start(tmp_path: Path) -> None:
    resolver = RecordingResolver()
    ct_client = RecordingCtClient()
    http = RecordingHttpClient()

    outcome = _investigation_service(resolver, ct_client, http).run(
        _investigation_request(tmp_path)
    )

    values = {entity.value for entity in outcome.graph.entities}
    assert {DOMAIN, "203.0.113.10", f"portal.{DOMAIN}"} <= values
    assert outcome.warnings == ()
    assert resolver.calls
    assert ct_client.calls == [DOMAIN]
    assert '"action": "investigation_started"' in (tmp_path / "investigation.log").read_text(
        encoding="utf-8"
    )


def test_investigation_skips_out_of_scope_discovered_username(tmp_path: Path) -> None:
    resolver = RecordingResolver()
    ct_client = RecordingCtClient()
    http = RecordingAccountClient()

    outcome = _investigation_service(resolver, ct_client, http).run(
        _investigation_request(
            tmp_path,
            seed_type=EntityType.EMAIL,
            seed_value=f"alice@{DOMAIN}",
            depth=2,
            account_handle="another-user",
        )
    )

    assert any("out-of-scope username pivot 'alice'" in item for item in outcome.warnings)
    assert http.calls == []
    assert resolver.calls
    assert ct_client.calls == [DOMAIN]
    assert "alice" in (tmp_path / "investigation.log").read_text(encoding="utf-8")


class _OutOfScopeCtClient(RecordingCtClient):
    """CT double returning a target-controlled subdomain outside the engagement."""

    def __init__(self, discovered: str) -> None:
        super().__init__()
        self._discovered = discovered

    def discover(self, domain: str) -> list[str]:
        self.calls.append(domain)
        return [self._discovered]


def test_investigation_does_not_resolve_out_of_scope_discovered_subdomain(tmp_path: Path) -> None:
    """SEC-H: a CT-discovered subdomain outside scope must never become a
    second-order network lookup.

    Certificate Transparency results are controlled by the target's own
    infrastructure, so a hostile CT entry could name an arbitrary host (a scope
    evasion / SSRF-of-second-order vector). The engagement scope gate is applied
    to every *discovered* pivot, not only the seed, so the out-of-scope host is
    added to the graph for the record but is never resolved.
    """
    evil = "internal.attacker.example"
    resolver = RecordingResolver()
    ct_client = _OutOfScopeCtClient(evil)
    http = RecordingHttpClient()

    outcome = _investigation_service(resolver, ct_client, http).run(
        _investigation_request(tmp_path, depth=2)
    )

    # Hop 1 ran against the authorized seed: the CT lookup and the seed's own
    # DNS resolution happened.
    assert ct_client.calls == [DOMAIN]
    assert resolver.calls
    assert any(name == DOMAIN for name, _ in resolver.calls)
    # The out-of-scope discovered subdomain is NEVER passed to the resolver.
    assert all(name != evil for name, _ in resolver.calls)
    # It is skipped and audited rather than silently followed or silently dropped.
    assert any(f"out-of-scope host pivot {evil!r}" in warning for warning in outcome.warnings)
    assert evil in (tmp_path / "investigation.log").read_text(encoding="utf-8")


def test_domain_scan_service_returns_recon_without_cli_dependency(tmp_path: Path) -> None:
    resolver = RecordingResolver()
    ct_client = RecordingCtClient()
    service = DomainScanService(resolver, ct_client)

    result = service.run(
        DomainScanRequest(DOMAIN, _scope(tmp_path / "scope.json"), tmp_path / "audit.log")
    )

    assert result.domain == DOMAIN
    assert result.a_records == ["203.0.113.10"]
    assert result.subdomains == [f"portal.{DOMAIN}"]
    assert resolver.calls
    assert ct_client.calls == [DOMAIN]


def test_email_service_offline_does_not_call_network() -> None:
    resolver = RecordingResolver()
    http = RecordingHttpClient()

    intel = EmailAnalysisService(resolver, http).run(EmailAnalysisRequest(f"alice@{DOMAIN}"))

    assert intel.report.email == f"alice@{DOMAIN}"
    assert intel.enrichment is None
    assert resolver.calls == []
    assert http.calls == []


def test_email_service_requires_authorization_before_network(tmp_path: Path) -> None:
    resolver = RecordingResolver()
    http = RecordingHttpClient()

    with pytest.raises(AuthorizationRequiredError):
        EmailAnalysisService(resolver, http).run(
            EmailAnalysisRequest(
                f"alice@{DOMAIN}",
                enrich=True,
                scope_path=_scope(tmp_path / "scope.json"),
                audit_log_path=tmp_path / "audit.log",
            )
        )

    assert resolver.calls == []
    assert http.calls == []


def test_email_service_blocks_out_of_scope_before_network(tmp_path: Path) -> None:
    resolver = RecordingResolver()
    http = RecordingHttpClient()
    audit_log = tmp_path / "audit.log"

    with pytest.raises(OutOfScopeError):
        EmailAnalysisService(resolver, http).run(
            EmailAnalysisRequest(
                "alice@outside.example",
                enrich=True,
                authorized=True,
                scope_path=_scope(tmp_path / "scope.json"),
                audit_log_path=audit_log,
            )
        )

    assert resolver.calls == []
    assert http.calls == []
    assert "outside.example" in audit_log.read_text(encoding="utf-8")


def test_mac_service_offline_does_not_call_network() -> None:
    http = RecordingHttpClient()

    intel = MacAnalysisService(http).run(MacAnalysisRequest("00:1A:2B:3C:4D:5E"))

    assert intel.report.oui == "00:1A:2B"
    assert intel.vendor is None
    assert http.calls == []


def test_mac_service_requires_authorization_before_network(tmp_path: Path) -> None:
    http = RecordingHttpClient()

    with pytest.raises(AuthorizationRequiredError):
        MacAnalysisService(http).run(
            MacAnalysisRequest(
                "00:1A:2B:3C:4D:5E",
                vendor=True,
                scope_path=_mac_scope(tmp_path / "scope.json"),
                audit_log_path=tmp_path / "audit.log",
            )
        )

    assert http.calls == []


def test_mac_service_blocks_out_of_scope_before_network(tmp_path: Path) -> None:
    http = RecordingHttpClient()
    audit_log = tmp_path / "audit.log"

    with pytest.raises(MacOutOfScopeError):
        MacAnalysisService(http).run(
            MacAnalysisRequest(
                "00:11:22:33:44:55",
                vendor=True,
                authorized=True,
                scope_path=_mac_scope(tmp_path / "scope.json"),
                audit_log_path=audit_log,
            )
        )

    assert http.calls == []
    assert "00:11:22:33:44:55" in audit_log.read_text(encoding="utf-8")


def test_mac_service_authorized_lookup_uses_injected_http(tmp_path: Path) -> None:
    http = RecordingHttpClient()

    intel = MacAnalysisService(http).run(
        MacAnalysisRequest(
            "00:1A:2B:3C:4D:5E",
            vendor=True,
            authorized=True,
            scope_path=_mac_scope(tmp_path / "scope.json"),
            audit_log_path=tmp_path / "audit.log",
        )
    )

    assert intel.vendor
    assert http.calls == ["https://api.macvendors.com/001A2B"]


def test_myip_service_skips_geo_port_when_not_requested() -> None:
    discovery = RecordingMyIpClient()
    geo = RecordingGeoClient()

    result = MyIpDiscoveryService(discovery, geo).run(MyIpDiscoveryRequest())

    assert result.public_ip == "203.0.113.7"
    assert result.intel is None
    assert discovery.calls == [PROVIDERS[0]]
    assert geo.calls == []


def test_myip_service_uses_independent_geo_port() -> None:
    discovery = RecordingMyIpClient()
    geo = RecordingGeoClient()

    result = MyIpDiscoveryService(discovery, geo).run(MyIpDiscoveryRequest(geolocate=True))

    assert result.intel is not None
    assert result.intel.report.ip == "203.0.113.7"
    assert discovery.calls == [PROVIDERS[0]]
    assert len(geo.calls) == 1
    assert "ipwho.is" in geo.calls[0]


def test_myip_service_reports_provider_failure_without_geo_call() -> None:
    discovery = RecordingMyIpClient(available=False)
    geo = RecordingGeoClient()

    with pytest.raises(MyIpError, match="could not determine public IP"):
        MyIpDiscoveryService(discovery, geo).run(MyIpDiscoveryRequest(geolocate=True))

    assert discovery.calls == list(PROVIDERS)
    assert geo.calls == []


def test_phone_service_offline_does_not_call_enrichment_ports(tmp_path: Path) -> None:
    carrier = RecordingPhoneEnrichmentClient(PhoneEnrichment(carrier="Example"))
    breach = RecordingPhoneEnrichmentClient(PhoneEnrichment(breach_count=1))
    messaging = RecordingMessagingClient()
    service = PhoneProfileService(carrier, breach, messaging)

    outcome = service.run(
        PhoneProfileRequest(
            "+16505550123",
            _phone_scope(tmp_path / "scope.json"),
            tmp_path / "audit.log",
        )
    )

    assert outcome.intel.report.e164 == "+16505550123"
    assert carrier.calls == []
    assert breach.calls == []
    assert messaging.calls == []


def test_phone_service_requires_authorization_before_network(tmp_path: Path) -> None:
    breach = RecordingPhoneEnrichmentClient(PhoneEnrichment(breach_count=1))

    with pytest.raises(AuthorizationRequiredError):
        PhoneProfileService(breach_client=breach).run(
            PhoneProfileRequest(
                "+16505550123",
                _phone_scope(tmp_path / "scope.json"),
                tmp_path / "audit.log",
                breach=True,
            )
        )

    assert breach.calls == []


def test_phone_service_blocks_out_of_scope_before_network(tmp_path: Path) -> None:
    breach = RecordingPhoneEnrichmentClient(PhoneEnrichment(breach_count=1))
    audit = tmp_path / "audit.log"

    with pytest.raises(PhoneOutOfScopeError):
        PhoneProfileService(breach_client=breach).run(
            PhoneProfileRequest(
                "+14155550123",
                _phone_scope(tmp_path / "scope.json"),
                audit,
                breach=True,
                authorized=True,
            )
        )

    assert breach.calls == []
    assert "+14155550123" in audit.read_text(encoding="utf-8")


def test_phone_service_preserves_authorized_enrichment_in_contract(tmp_path: Path) -> None:
    carrier = RecordingPhoneEnrichmentClient(
        PhoneEnrichment(carrier="Example Mobile", line_type="mobile")
    )
    breach = RecordingPhoneEnrichmentClient(
        PhoneEnrichment(breach_count=2, breach_sources=("Example",))
    )
    messaging = RecordingMessagingClient()

    outcome = PhoneProfileService(carrier, breach, messaging).run(
        PhoneProfileRequest(
            "+16505550123",
            _phone_scope(tmp_path / "scope.json"),
            tmp_path / "audit.log",
            enrich=True,
            breach=True,
            messaging=True,
            authorized=True,
        )
    )

    payload = outcome.intel.to_dict()
    assert payload["enrichment"] == {
        "carrier": "Example Mobile",
        "line_type": "mobile",
        "breach_count": 2,
        "breach_sources": ["Example"],
    }
    messaging_payload = payload["messaging"]
    assert isinstance(messaging_payload, dict)
    assert messaging_payload["registered"] is True
    assert outcome.intel.asset.metadata["enrichment_carrier"] == "Example Mobile"
    assert len(outcome.intel.findings) == 2


def test_phone_batch_records_skips_without_calling_network(tmp_path: Path) -> None:
    breach = RecordingPhoneEnrichmentClient(PhoneEnrichment(breach_count=1))
    scope = _phone_scope(tmp_path / "scope.json")
    audit = tmp_path / "audit.log"
    requests = tuple(
        PhoneProfileRequest(number, scope, audit)
        for number in ("+16505550123", "not-a-number", "+14155550123")
    )

    result = PhoneProfileService(breach_client=breach).run_many(requests)

    assert len(result.intels) == 1
    assert any("unparseable" in warning for warning in result.warnings)
    assert any("out-of-scope" in warning for warning in result.warnings)
    assert breach.calls == []


def test_ip_service_offline_does_not_call_geo_port(tmp_path: Path) -> None:
    geo = RecordingIpGeoClient()

    outcome = IpProfileService(geo).run(
        IpProfileRequest(
            "203.0.113.10",
            _ip_scope(tmp_path / "scope.json"),
            tmp_path / "audit.log",
        )
    )

    assert outcome.intel.report.ip == "203.0.113.10"
    assert outcome.intel.geo is None
    assert geo.calls == []


def test_ip_service_requires_authorization_before_geo(tmp_path: Path) -> None:
    geo = RecordingIpGeoClient()

    with pytest.raises(AuthorizationRequiredError):
        IpProfileService(geo).run(
            IpProfileRequest(
                "203.0.113.10",
                _ip_scope(tmp_path / "scope.json"),
                tmp_path / "audit.log",
                geolocate=True,
            )
        )

    assert geo.calls == []


def test_ip_service_blocks_out_of_scope_before_geo(tmp_path: Path) -> None:
    geo = RecordingIpGeoClient()
    audit = tmp_path / "audit.log"

    with pytest.raises(IpOutOfScopeError):
        IpProfileService(geo).run(
            IpProfileRequest(
                "8.8.8.8",
                _ip_scope(tmp_path / "scope.json"),
                audit,
                geolocate=True,
                authorized=True,
            )
        )

    assert geo.calls == []
    assert "8.8.8.8" in audit.read_text(encoding="utf-8")


def test_ip_service_preserves_geo_in_contract(tmp_path: Path) -> None:
    geo = RecordingIpGeoClient()

    outcome = IpProfileService(geo).run(
        IpProfileRequest(
            "203.0.113.10",
            _ip_scope(tmp_path / "scope.json"),
            tmp_path / "audit.log",
            geolocate=True,
            authorized=True,
        )
    )

    payload = outcome.intel.to_dict()
    assert geo.calls == ["203.0.113.10"]
    geo_payload = payload["geo"]
    assert isinstance(geo_payload, dict)
    assert geo_payload["asn"] == "AS64500"
    assert outcome.intel.asset.metadata["country"] == "Example"


def test_ip_batch_records_invalid_and_scope_skips(tmp_path: Path) -> None:
    scope = _ip_scope(tmp_path / "scope.json")
    audit = tmp_path / "audit.log"
    requests = tuple(
        IpProfileRequest(ip, scope, audit) for ip in ("203.0.113.10", "not-an-ip", "8.8.8.8")
    )

    result = IpProfileService().run_many(requests)

    assert len(result.intels) == 1
    assert any("invalid IP" in warning for warning in result.warnings)
    assert any("out-of-scope" in warning for warning in result.warnings)


def test_account_service_requires_authorization_before_metadata_network(tmp_path: Path) -> None:
    http = RecordingAccountClient()

    with pytest.raises(AuthorizationRequiredError):
        AccountEnumerationService(_account_specs(), http).run(
            AccountEnumerationRequest(
                "olympus_demo",
                _account_scope(tmp_path / "scope.json"),
                tmp_path / "audit.log",
                metadata=True,
            )
        )

    assert http.calls == []


def test_account_service_blocks_out_of_scope_before_network(tmp_path: Path) -> None:
    http = RecordingAccountClient()
    audit = tmp_path / "audit.log"

    with pytest.raises(AccountOutOfScopeError):
        AccountEnumerationService(_account_specs(), http).run(
            AccountEnumerationRequest(
                "intruder",
                _account_scope(tmp_path / "scope.json"),
                audit,
            )
        )

    assert http.calls == []
    assert "intruder" in audit.read_text(encoding="utf-8")


def test_account_service_preserves_success_and_partial_results(tmp_path: Path) -> None:
    http = RecordingAccountClient()

    outcome = AccountEnumerationService(_account_specs(), http).run(
        AccountEnumerationRequest(
            "olympus_demo",
            _account_scope(tmp_path / "scope.json"),
            tmp_path / "audit.log",
            metadata=True,
            authorized=True,
            concurrency=2,
        )
    )

    checks = outcome.intel.result.checks
    assert [check.exists for check in checks] == [True, None]
    assert checks[0].metadata == {"bio": "example"}
    assert len(outcome.intel.assets) == 1
    assert len(http.calls) == 2


def test_account_batch_records_scope_skip(tmp_path: Path) -> None:
    http = RecordingAccountClient()
    scope = _account_scope(tmp_path / "scope.json")
    audit = tmp_path / "audit.log"

    result = AccountEnumerationService(_account_specs(), http).run_many(
        tuple(
            AccountEnumerationRequest(handle, scope, audit)
            for handle in ("olympus_demo", "intruder")
        )
    )

    assert len(result.intels) == 1
    assert result.warnings == ("skipping out-of-scope handle 'intruder' (logged)",)
    assert len(http.calls) == 2


def test_account_service_rejects_unsafe_concurrency_before_network(tmp_path: Path) -> None:
    http = RecordingAccountClient()

    with pytest.raises(ValueError, match="concurrency"):
        AccountEnumerationService(_account_specs(), http).run(
            AccountEnumerationRequest(
                "olympus_demo",
                _account_scope(tmp_path / "scope.json"),
                tmp_path / "audit.log",
                concurrency=65,
            )
        )

    assert http.calls == []


def test_domain_scan_service_blocks_before_network_dependencies(tmp_path: Path) -> None:
    resolver = RecordingResolver()
    ct_client = RecordingCtClient()
    audit_log = tmp_path / "audit.log"
    service = DomainScanService(resolver, ct_client)

    with pytest.raises(OutOfScopeError):
        service.run(
            DomainScanRequest(
                "outside.example",
                _scope(tmp_path / "scope.json"),
                audit_log,
            )
        )

    assert resolver.calls == []
    assert ct_client.calls == []
    assert "outside.example" in audit_log.read_text(encoding="utf-8")


def test_fronting_service_runs_without_cli_dependency(tmp_path: Path) -> None:
    resolver = RecordingResolver()
    ct_client = RecordingCtClient()

    result = FrontingAssessmentService(resolver, ct_client).run(
        FrontingAssessmentRequest(DOMAIN, _scope(tmp_path / "scope.json"), tmp_path / "audit.log")
    )

    assert result.domain == DOMAIN
    assert resolver.calls == [(DOMAIN, "A"), (DOMAIN, "AAAA")]
    # A non-fronted apex intentionally avoids CT fan-out.
    assert ct_client.calls == []


def test_fronting_service_blocks_before_network_dependencies(tmp_path: Path) -> None:
    resolver = RecordingResolver()
    ct_client = RecordingCtClient()
    audit_log = tmp_path / "audit.log"

    with pytest.raises(OutOfScopeError):
        FrontingAssessmentService(resolver, ct_client).run(
            FrontingAssessmentRequest("outside.example", _scope(tmp_path / "scope.json"), audit_log)
        )

    assert resolver.calls == []
    assert ct_client.calls == []
    assert "outside.example" in audit_log.read_text(encoding="utf-8")


def test_fronting_service_rejects_invalid_limit_before_network(tmp_path: Path) -> None:
    resolver = RecordingResolver()
    ct_client = RecordingCtClient()

    with pytest.raises(ValueError, match="max_subdomains"):
        FrontingAssessmentService(resolver, ct_client).run(
            FrontingAssessmentRequest(
                DOMAIN,
                _scope(tmp_path / "scope.json"),
                tmp_path / "audit.log",
                max_subdomains=-1,
            )
        )

    assert resolver.calls == []
    assert ct_client.calls == []


def test_dns_lookup_service_runs_without_cli_dependency(tmp_path: Path) -> None:
    http = RecordingHttpClient()

    result = DnsLookupService(http).run(
        DnsLookupRequest(
            DOMAIN,
            _scope(tmp_path / "scope.json"),
            tmp_path / "audit.log",
            record_types=("a",),
        )
    )

    assert result.records == {"A": ["203.0.113.20"]}
    assert len(http.calls) == 1
    assert "type=A" in http.calls[0]


def test_dns_lookup_service_blocks_before_http(tmp_path: Path) -> None:
    http = RecordingHttpClient()
    audit_log = tmp_path / "audit.log"

    with pytest.raises(OutOfScopeError):
        DnsLookupService(http).run(
            DnsLookupRequest(
                "outside.example",
                _scope(tmp_path / "scope.json"),
                audit_log,
                record_types=("A",),
            )
        )

    assert http.calls == []
    assert "outside.example" in audit_log.read_text(encoding="utf-8")


def test_dns_lookup_service_rejects_empty_types_before_http(tmp_path: Path) -> None:
    http = RecordingHttpClient()

    with pytest.raises(ValueError, match="record_types"):
        DnsLookupService(http).run(
            DnsLookupRequest(
                DOMAIN,
                _scope(tmp_path / "scope.json"),
                tmp_path / "audit.log",
                record_types=(),
            )
        )

    assert http.calls == []


def test_whois_lookup_service_runs_without_cli_dependency(tmp_path: Path) -> None:
    http = RecordingRdapClient()

    result = WhoisLookupService(http).run(
        WhoisLookupRequest(DOMAIN, _scope(tmp_path / "scope.json"), tmp_path / "audit.log")
    )

    assert result.domain == DOMAIN.upper()
    assert result.status == ["active"]
    assert http.calls == [f"https://rdap.org/domain/{DOMAIN}"]


def test_whois_lookup_service_blocks_before_http(tmp_path: Path) -> None:
    http = RecordingRdapClient()
    audit_log = tmp_path / "audit.log"

    with pytest.raises(OutOfScopeError):
        WhoisLookupService(http).run(
            WhoisLookupRequest("outside.example", _scope(tmp_path / "scope.json"), audit_log)
        )

    assert http.calls == []
    assert "outside.example" in audit_log.read_text(encoding="utf-8")


def test_web_recon_service_returns_shared_contracts(tmp_path: Path) -> None:
    http = RecordingWebClient()

    intel = WebReconService(http).run(
        WebReconRequest(DOMAIN, _scope(tmp_path / "scope.json"), tmp_path / "audit.log")
    )

    assert intel.report.url == f"https://{DOMAIN}"
    assert intel.asset.hostname == DOMAIN
    assert len(intel.findings) == 2
    assert http.calls == [f"https://{DOMAIN}"]


def test_web_recon_service_blocks_before_http(tmp_path: Path) -> None:
    http = RecordingWebClient()
    audit_log = tmp_path / "audit.log"

    with pytest.raises(OutOfScopeError):
        WebReconService(http).run(
            WebReconRequest("outside.example", _scope(tmp_path / "scope.json"), audit_log)
        )

    assert http.calls == []
    assert "outside.example" in audit_log.read_text(encoding="utf-8")


def test_web_recon_service_rejects_invalid_url_before_http(tmp_path: Path) -> None:
    http = RecordingWebClient()

    with pytest.raises(InvalidWebTargetError):
        WebReconService(http).run(
            WebReconRequest(
                "https:///missing-host",
                tmp_path / "scope.json",
                tmp_path / "audit.log",
            )
        )

    assert http.calls == []
