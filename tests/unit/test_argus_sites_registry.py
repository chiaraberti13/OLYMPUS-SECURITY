"""Validate the shipped account-enumeration site registry loads and is well-formed."""

import re
from pathlib import Path

from olympus.argus.accounts import check_site, load_site_registry
from olympus.core.http import HttpResponse

REGISTRY = Path("examples/input/argus-sites.json")


class _Reflecting:
    """Return a body embedding a TikTok-style followerCount for the target site."""

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        return HttpResponse(status_code=200, headers={}, body='x "followerCount":4242 y')


def test_registry_loads_and_templates_are_valid() -> None:
    specs = load_site_registry(REGISTRY)
    names = {spec.name for spec in specs}
    assert {"GitHub", "TikTok", "YouTube"} <= names
    for spec in specs:
        assert "{username}" in spec.url_template
        for pattern in spec.metadata_patterns.values():
            re.compile(pattern)  # every metadata pattern must be a valid regex


def test_tiktok_follower_metadata_extraction() -> None:
    specs = {spec.name: spec for spec in load_site_registry(REGISTRY)}
    check = check_site("someone", specs["TikTok"], _Reflecting(), want_metadata=True)
    assert check.exists is True
    assert check.metadata["followers"] == "4242"
