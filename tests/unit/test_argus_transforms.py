"""Unit tests for Argus investigation transforms (all clients are fakes)."""

import json

from olympus.argus.accounts import SiteSpec
from olympus.argus.graph import Entity, EntityType, Investigation
from olympus.argus.transforms import (
    TransformContext,
    domain_ct_transform,
    domain_dns_transform,
    email_transform,
    ip_geo_transform,
    phone_transform,
    run_investigation,
    username_accounts_transform,
)
from olympus.core.http import HttpResponse


class _Resolver:
    def resolve(self, name: str, record_type: str) -> list[str]:
        if record_type == "A":
            return ["203.0.113.10"]
        if record_type == "AAAA":
            return ["2001:db8::10"]
        return []


class _CtClient:
    def discover(self, domain: str) -> list[str]:
        return [domain, f"mail.{domain}", f"vpn.{domain}"]


class _HttpClient:
    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        if "ipwho.is" in url:
            body = json.dumps(
                {
                    "success": True,
                    "country": "Italy",
                    "city": "Rome",
                    "connection": {"isp": "ISP", "asn": 64500},
                }
            )
            return HttpResponse(status_code=200, headers={}, body=body)
        if "github.com" in url:  # username account presence
            return HttpResponse(status_code=200, headers={}, body="profile")
        return HttpResponse(status_code=404, headers={}, body="")


def test_phone_transform_enriches_attributes() -> None:
    graph = Investigation("t")
    phone = graph.add_entity(Entity(EntityType.PHONE, "+16505550123"))
    assert phone_transform(phone, graph, TransformContext()) == []
    assert phone.attributes["region"] == "US"
    assert phone.attributes["e164"] == "+16505550123"


def test_email_transform_splits_username_and_domain() -> None:
    graph = Investigation("t")
    email = graph.add_entity(Entity(EntityType.EMAIL, "alice@example.com"))
    new = email_transform(email, graph, TransformContext())
    types = {e.entity_type for e in new}
    assert types == {EntityType.USERNAME, EntityType.DOMAIN}
    assert len(graph.relationships) == 2


def test_domain_dns_transform_adds_ips() -> None:
    graph = Investigation("t")
    domain = graph.add_entity(Entity(EntityType.DOMAIN, "x.example"))
    new = domain_dns_transform(domain, graph, TransformContext(resolver=_Resolver()))
    values = {e.value for e in new}
    assert values == {"203.0.113.10", "2001:db8::10"}


def test_domain_ct_transform_adds_subdomains_excluding_self() -> None:
    graph = Investigation("t")
    domain = graph.add_entity(Entity(EntityType.DOMAIN, "x.example"))
    new = domain_ct_transform(domain, graph, TransformContext(ct_client=_CtClient()))
    values = {e.value for e in new}
    assert values == {"mail.x.example", "vpn.x.example"}  # self excluded


def test_ip_geo_transform_enriches_and_adds_asn() -> None:
    graph = Investigation("t")
    ip = graph.add_entity(Entity(EntityType.IP, "1.1.1.1"))
    ctx = TransformContext(http=_HttpClient(), geolocate=True)
    new = ip_geo_transform(ip, graph, ctx)
    assert ip.attributes["country"] == "Italy"
    assert new[0].entity_type is EntityType.ASN


def test_ip_geo_transform_offline_only_sets_kind() -> None:
    graph = Investigation("t")
    ip = graph.add_entity(Entity(EntityType.IP, "10.0.0.1"))
    assert ip_geo_transform(ip, graph, TransformContext(geolocate=False)) == []
    assert ip.attributes["kind"] == "private"


def test_username_accounts_transform_adds_accounts() -> None:
    graph = Investigation("t")
    user = graph.add_entity(Entity(EntityType.USERNAME, "bob"))
    specs = [
        SiteSpec(name="GitHub", url_template="https://github.com/{username}"),
        SiteSpec(name="GitLab", url_template="https://gitlab.com/{username}"),
    ]
    ctx = TransformContext(http=_HttpClient(), site_specs=specs)
    new = username_accounts_transform(user, graph, ctx)
    assert len(new) == 1  # only github "exists"
    assert new[0].attributes["site"] == "GitHub"


def test_run_investigation_expands_by_depth() -> None:
    specs = [SiteSpec(name="GitHub", url_template="https://github.com/{username}")]
    ctx = TransformContext(
        resolver=_Resolver(), ct_client=_CtClient(), http=_HttpClient(), site_specs=specs
    )
    # depth 2: email -> username/domain -> (username: accounts) + (domain: dns/ct)
    graph = run_investigation("case", EntityType.EMAIL, "bob@x.example", ctx, depth=2)
    types = {e.entity_type for e in graph.entities}
    assert EntityType.USERNAME in types
    assert EntityType.DOMAIN in types
    assert EntityType.IP in types  # domain expanded via DNS at depth 2
    assert EntityType.ACCOUNT in types  # username expanded via accounts at depth 2


def test_run_investigation_depth_zero_is_seed_only() -> None:
    graph = run_investigation("case", EntityType.EMAIL, "b@x.example", TransformContext(), depth=0)
    assert len(graph.entities) == 1
