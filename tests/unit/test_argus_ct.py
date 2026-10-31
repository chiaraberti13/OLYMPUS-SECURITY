"""Offline tests for passive Certificate Transparency discovery."""

from pathlib import Path

import pytest

from olympus.argus.ct import CertificateTransparencyError, parse_crtsh_response

DOMAIN = "olympusdemocorp.example"
FIXTURE = Path("tests/fixtures/argus/crtsh.json")


def test_parse_crtsh_fixture_extracts_unique_in_scope_subdomains() -> None:
    subdomains = parse_crtsh_response(DOMAIN, FIXTURE.read_text(encoding="utf-8"))

    assert subdomains == [
        "api.olympusdemocorp.example",
        "portal.olympusdemocorp.example",
    ]


@pytest.mark.parametrize("payload", ["not json", "{}"])
def test_parse_crtsh_response_rejects_invalid_payload(payload: str) -> None:
    with pytest.raises(CertificateTransparencyError):
        parse_crtsh_response(DOMAIN, payload)
