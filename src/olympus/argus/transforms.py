"""Transforms: pivot from one investigation entity to related ones.

Each transform reuses an existing Argus primitive (phone parsing, DNS, CT,
IP geolocation, account enumeration) and is driven through injected clients,
so the whole investigation engine runs offline in tests and against the real
network in production. Transforms are pure with respect to the graph: they
add entities/edges and return the newly discovered entities so the engine
can pivot again up to a bounded depth.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from olympus.argus.accounts import SiteSpec, enumerate_accounts
from olympus.argus.ct import CertificateTransparencyClient, CertificateTransparencyError
from olympus.argus.graph import Entity, EntityType, Investigation
from olympus.argus.ip_osint import IpGeoError, IpParseError, IpWhoisClient, analyze_ip
from olympus.argus.phone import PhoneParseError, analyze_phone
from olympus.argus.resolver import DnsResolutionError, DnsResolver
from olympus.core.http import HttpClient


@dataclass
class TransformContext:
    """Injected clients + config the transforms need (offline doubles in tests)."""

    resolver: DnsResolver | None = None
    ct_client: CertificateTransparencyClient | None = None
    http: HttpClient | None = None
    site_specs: list[SiteSpec] = field(default_factory=list)
    geolocate: bool = False
    scope_guard: Callable[[Entity], bool] | None = None
    warnings: list[str] = field(default_factory=list)


# A transform takes an entity + the graph + context and returns new entities.
Transform = Callable[[Entity, Investigation, TransformContext], list[Entity]]


def _network_allowed(entity: Entity, ctx: TransformContext) -> bool:
    """Apply the injected engagement gate immediately before a network transform."""
    return ctx.scope_guard is None or ctx.scope_guard(entity)


def phone_transform(entity: Entity, graph: Investigation, ctx: TransformContext) -> list[Entity]:
    """Enrich a phone entity with offline-parsed carrier/region/line-type."""
    try:
        report = analyze_phone(entity.value)
    except PhoneParseError:
        return []
    if report.e164:
        entity.attributes["e164"] = report.e164
    for key, value in (
        ("region", report.region_code or ""),
        ("location", report.location),
        ("carrier", report.carrier_name),
        ("line_type", report.line_type),
    ):
        if value:
            entity.attributes[key] = value
    return []


def email_transform(entity: Entity, graph: Investigation, ctx: TransformContext) -> list[Entity]:
    """Split an email into its username (local part) and domain entities."""
    local, _, domain = entity.value.partition("@")
    if not local or not domain:
        return []
    new: list[Entity] = []
    username = graph.add_entity(Entity(EntityType.USERNAME, local, discovered_by="email"))
    graph.add_relationship(entity, username, "local_part")
    new.append(username)
    domain_entity = graph.add_entity(Entity(EntityType.DOMAIN, domain, discovered_by="email"))
    graph.add_relationship(entity, domain_entity, "domain")
    new.append(domain_entity)
    return new


def domain_dns_transform(
    entity: Entity, graph: Investigation, ctx: TransformContext
) -> list[Entity]:
    """Resolve a domain to its A/AAAA addresses, adding IP entities."""
    if ctx.resolver is None or not _network_allowed(entity, ctx):
        return []
    new: list[Entity] = []
    for record_type in ("A", "AAAA"):
        try:
            addresses = ctx.resolver.resolve(entity.value, record_type)
        except DnsResolutionError:
            ctx.warnings.append(f"DNS {record_type} lookup failed for {entity.value!r}")
            continue
        for address in addresses:
            ip_entity = graph.add_entity(Entity(EntityType.IP, address, discovered_by="dns"))
            graph.add_relationship(entity, ip_entity, "resolves_to")
            new.append(ip_entity)
    return new


def domain_ct_transform(
    entity: Entity, graph: Investigation, ctx: TransformContext
) -> list[Entity]:
    """Discover subdomains of a domain via Certificate Transparency."""
    if ctx.ct_client is None or not _network_allowed(entity, ctx):
        return []
    new: list[Entity] = []
    try:
        subdomains = ctx.ct_client.discover(entity.value)
    except CertificateTransparencyError:
        ctx.warnings.append(f"Certificate Transparency lookup failed for {entity.value!r}")
        return []
    for subdomain in subdomains:
        if subdomain == entity.value:
            continue
        host = graph.add_entity(Entity(EntityType.HOST, subdomain, discovered_by="ct"))
        graph.add_relationship(entity, host, "subdomain")
        new.append(host)
    return new


def ip_geo_transform(entity: Entity, graph: Investigation, ctx: TransformContext) -> list[Entity]:
    """Enrich an IP with offline classification, and (opt-in) geolocation/ASN."""
    try:
        report = analyze_ip(entity.value)
    except IpParseError:
        ctx.warnings.append(f"invalid IP pivot skipped: {entity.value!r}")
        return []
    entity.attributes["kind"] = report.kind
    if not (ctx.geolocate and ctx.http is not None) or not _network_allowed(entity, ctx):
        return []
    try:
        geo = IpWhoisClient(ctx.http).geolocate(entity.value)
    except IpGeoError:
        ctx.warnings.append(f"IP geolocation failed for {entity.value!r}")
        return []
    for key, value in (("country", geo.country), ("city", geo.city), ("isp", geo.isp)):
        if value:
            entity.attributes[key] = value
    if not geo.asn:
        return []
    asn_entity = graph.add_entity(Entity(EntityType.ASN, geo.asn, discovered_by="ip-geo"))
    graph.add_relationship(entity, asn_entity, "announced_by")
    return [asn_entity]


def username_accounts_transform(
    entity: Entity, graph: Investigation, ctx: TransformContext
) -> list[Entity]:
    """Find public accounts for a username across the curated site registry."""
    if ctx.http is None or not ctx.site_specs or not _network_allowed(entity, ctx):
        return []
    result = enumerate_accounts(entity.value, ctx.site_specs, ctx.http)
    new: list[Entity] = []
    for check in result.existing():
        account = graph.add_entity(
            Entity(
                EntityType.ACCOUNT,
                check.url,
                attributes={"site": check.name, "handle": entity.value},
                discovered_by="account-enum",
            )
        )
        graph.add_relationship(entity, account, "has_account")
        new.append(account)
    return new


# Which transforms apply to which seed entity type.
TRANSFORMS: dict[EntityType, list[Transform]] = {
    EntityType.PHONE: [phone_transform],
    EntityType.EMAIL: [email_transform],
    EntityType.DOMAIN: [domain_dns_transform, domain_ct_transform],
    EntityType.HOST: [domain_dns_transform],
    EntityType.IP: [ip_geo_transform],
    EntityType.USERNAME: [username_accounts_transform],
}


def run_investigation(
    name: str,
    seed_type: EntityType,
    seed_value: str,
    ctx: TransformContext,
    *,
    depth: int = 1,
) -> Investigation:
    """Seed a graph and expand it by applying transforms up to ``depth`` hops."""
    graph = Investigation(name)
    seed = graph.add_entity(Entity(seed_type, seed_value))
    frontier = [seed]
    for _ in range(max(depth, 0)):
        next_frontier: list[Entity] = []
        for entity in frontier:
            for transform in TRANSFORMS.get(entity.entity_type, []):
                next_frontier.extend(transform(entity, graph, ctx))
        if not next_frontier:
            break
        frontier = next_frontier
    return graph
