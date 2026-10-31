"""Unit tests for Argus passive DNS recon, against an offline fixture resolver.

The fixture models a synthetic "Olympus Demo Corp" domain using only
IANA-reserved documentation ranges (RFC 5737 / RFC 3849), so nothing here
ever touches a real host.
"""

from __future__ import annotations

from olympus.argus.recon import DomainRecon, scan_domain

DOMAIN = "olympusdemocorp.example"


class FakeResolver:
    """Offline :class:`DnsResolver` double backed by an in-memory fixture."""

    def __init__(self, records: dict[tuple[str, str], list[str]]) -> None:
        self._records = records

    def resolve(self, name: str, record_type: str) -> list[str]:
        return list(self._records.get((name.lower(), record_type), []))


def demo_corp_resolver() -> FakeResolver:
    """Return a fixture resolver with a full "Olympus Demo Corp" DNS posture."""
    return FakeResolver(
        {
            (DOMAIN, "A"): ["203.0.113.10"],
            (DOMAIN, "AAAA"): ["2001:db8::10"],
            (DOMAIN, "MX"): ["10 mail.olympusdemocorp.example"],
            (DOMAIN, "TXT"): [
                "v=spf1 include:_spf.olympusdemocorp.example ~all",
                "some-unrelated-txt-record",
            ],
            (f"_dmarc.{DOMAIN}", "TXT"): [
                "v=DMARC1; p=reject; rua=mailto:dmarc@olympusdemocorp.example"
            ],
        }
    )


def test_scan_domain_collects_all_record_types() -> None:
    result = scan_domain(DOMAIN, demo_corp_resolver())

    assert isinstance(result, DomainRecon)
    assert result.domain == DOMAIN
    assert result.a_records == ["203.0.113.10"]
    assert result.aaaa_records == ["2001:db8::10"]
    assert result.mx_records == ["10 mail.olympusdemocorp.example"]
    assert result.spf == "v=spf1 include:_spf.olympusdemocorp.example ~all"
    assert result.dmarc == "v=DMARC1; p=reject; rua=mailto:dmarc@olympusdemocorp.example"


def test_scan_domain_handles_missing_spf_and_dmarc() -> None:
    resolver = FakeResolver(
        {
            (DOMAIN, "A"): ["203.0.113.10"],
            (DOMAIN, "TXT"): ["some-unrelated-txt-record"],
        }
    )
    result = scan_domain(DOMAIN, resolver)

    assert result.spf is None
    assert result.dmarc is None
    assert result.mx_records == []


def test_to_dict_is_json_serializable() -> None:
    result = scan_domain(DOMAIN, demo_corp_resolver())
    payload = result.to_dict()

    assert payload["domain"] == DOMAIN
    assert payload["a_records"] == ["203.0.113.10"]
    assert isinstance(payload["scanned_at"], str)


def test_scan_domain_includes_passive_ct_subdomains() -> None:
    class FakeCtClient:
        def discover(self, domain: str) -> list[str]:
            assert domain == DOMAIN
            return [f"portal.{domain}"]

    result = scan_domain(DOMAIN, demo_corp_resolver(), FakeCtClient())

    assert result.subdomains == ["portal.olympusdemocorp.example"]
