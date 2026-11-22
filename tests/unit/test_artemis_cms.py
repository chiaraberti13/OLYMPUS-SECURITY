"""Offline CMS version → advisory assessment (TOOLS-2, cms-scanner).

Covers the version algebra (parse, three-way compare, half-open range), the
fail-closed advisory-feed loader, and the assessment itself (CMS matching,
version-in-range findings, honest inference labelling, the unversioned path and
determinism). This file is also the committed evidence that backs the
``cms-scanner`` capability as *present* in
:mod:`olympus.integrations.suite_catalog`.
"""

from __future__ import annotations

import json

import pytest

from olympus.artemis.cms import (
    MAX_ADVISORIES,
    CmsAdvisory,
    CmsAdvisoryError,
    assess_cms,
    load_advisories,
    version_in_range,
)
from olympus.artemis.fingerprint import Fingerprint
from olympus.core.enums import Confidence, Severity, Source

pytestmark = pytest.mark.unit


# --- version algebra -------------------------------------------------------- #


def test_version_in_range_half_open_and_bounds() -> None:
    # [4.7, 4.7.2): includes the lower bound, excludes the upper.
    assert version_in_range("4.7", "4.7", "4.7.2")
    assert version_in_range("4.7.1", "4.7", "4.7.2")
    assert not version_in_range("4.7.2", "4.7", "4.7.2")
    assert not version_in_range("4.6.9", "4.7", "4.7.2")
    # Open lower bound: everything below fixed.
    assert version_in_range("3.0", None, "5.1.1")
    assert not version_in_range("5.1.1", None, "5.1.1")
    # Open upper bound: everything at/above introduced.
    assert version_in_range("9.9", "5.0", None)
    # No bounds at all: affects every (parseable) version.
    assert version_in_range("1.2.3", None, None)


def test_version_compare_zero_pads_and_ignores_suffixes() -> None:
    # "5" vs "5.0.0" compare equal (zero padding); suffixes are truncated.
    assert version_in_range("5", "5.0.0", "5.0.1")
    assert version_in_range("1.2.3-beta", "1.2.3", "1.2.4")  # suffix dropped -> 1.2.3


def test_unparseable_version_is_rejected() -> None:
    with pytest.raises(CmsAdvisoryError, match="unparseable version"):
        version_in_range("not-a-version", "1.0", None)


# --- advisory feed loader (fail-closed) ------------------------------------- #


def _feed() -> str:
    return json.dumps(
        [
            {
                "cms": "WordPress",
                "advisory_id": "CVE-2019-9787",
                "title": "CSRF to stored XSS in comments",
                "severity": "high",
                "introduced": None,
                "fixed": "5.1.1",
                "cves": ["CVE-2019-9787"],
                "cwes": ["CWE-352"],
                "references": ["https://example.test/advisory/1"],
                "remediation": "Upgrade to WordPress 5.1.1 or later.",
            },
            {
                "cms": "Drupal",
                "advisory_id": "SA-CORE-DEMO",
                "title": "Example Drupal core issue",
                "severity": "critical",
                "introduced": "7",
                "fixed": "8",
            },
        ]
    )


def test_load_advisories_parses_list_and_wrapper() -> None:
    from_list = load_advisories(_feed())
    assert len(from_list) == 2
    assert from_list[0].cms == "WordPress"
    assert from_list[0].severity is Severity.HIGH
    assert from_list[0].range_text() == "< 5.1.1"
    # The {"advisories": [...]} wrapper is also accepted.
    wrapped = load_advisories(json.dumps({"advisories": json.loads(_feed())}))
    assert len(wrapped) == 2


def test_load_advisories_rejects_malformed_and_unknown_severity() -> None:
    with pytest.raises(CmsAdvisoryError, match="invalid advisory JSON"):
        load_advisories("not json")
    with pytest.raises(CmsAdvisoryError, match="must be a JSON list"):
        load_advisories(json.dumps(42))
    with pytest.raises(CmsAdvisoryError, match="unknown severity"):
        load_advisories(
            json.dumps([{"cms": "X", "advisory_id": "A", "title": "T", "severity": "oops"}])
        )
    with pytest.raises(CmsAdvisoryError, match="non-empty string"):
        load_advisories(json.dumps([{"cms": "", "advisory_id": "A", "title": "T"}]))
    with pytest.raises(CmsAdvisoryError, match="unparseable version"):
        load_advisories(json.dumps([{"cms": "X", "advisory_id": "A", "title": "T", "fixed": "x"}]))


def test_load_advisories_is_bounded() -> None:
    too_many = json.dumps(
        [{"cms": "X", "advisory_id": f"A{i}", "title": "T"} for i in range(MAX_ADVISORIES + 1)]
    )
    with pytest.raises(CmsAdvisoryError, match="entry limit"):
        load_advisories(too_many)


# --- assessment ------------------------------------------------------------- #


def _cms_fp(product: str, version: str | None) -> Fingerprint:
    return Fingerprint(product=product, category="cms", version=version, evidence="matched on body")


def test_assess_matches_versions_in_range_and_labels_inference() -> None:
    advisories = load_advisories(_feed())
    fps = [
        _cms_fp("WordPress", "5.0.3"),  # < 5.1.1 -> matches CVE-2019-9787
        Fingerprint(product="nginx", category="web-server", version="1.25"),  # ignored (not cms)
    ]
    assessment = assess_cms(fps, advisories, asset_id="AST-1", url="https://wp.example/")
    assert len(assessment.findings) == 1
    finding = assessment.findings[0]
    assert finding.source is Source.ARTEMIS
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.MEDIUM  # version-based inference, never asserted
    assert finding.cve == ["CVE-2019-9787"]
    assert finding.cwe == ["CWE-352"]
    assert "CVE-2019-9787" in finding.title and "WordPress 5.0.3" in finding.title
    assert "version-based inference" in finding.description
    assert "plugin and theme enumeration is out of scope" in finding.description
    assert finding.remediation.startswith("Upgrade")
    assert set(finding.tags) == {"cms", "version-advisory"}
    assert assessment.assessed == (("WordPress", "5.0.3"),)
    assert assessment.advisories_considered == 2


def test_assess_excludes_patched_versions() -> None:
    advisories = load_advisories(_feed())
    assessment = assess_cms(
        [_cms_fp("WordPress", "5.1.1")], advisories, asset_id="A", url="https://x/"
    )
    assert assessment.findings == ()  # exactly the fixed version is no longer affected


def test_assess_is_case_insensitive_on_cms_name() -> None:
    advisories = load_advisories(_feed())
    assessment = assess_cms(
        [_cms_fp("wordpress", "5.0.0")], advisories, asset_id="A", url="https://x/"
    )
    assert len(assessment.findings) == 1


def test_assess_reports_unversioned_cms_and_assesses_nothing() -> None:
    advisories = load_advisories(_feed())
    assessment = assess_cms(
        [_cms_fp("WordPress", None)], advisories, asset_id="A", url="https://x/"
    )
    assert assessment.findings == ()
    assert assessment.unversioned == ("WordPress",)
    assert assessment.assessed == ()


def test_assess_is_deterministic_across_advisory_order() -> None:
    base = json.loads(_feed())
    wp_extra = {
        "cms": "WordPress",
        "advisory_id": "CVE-2018-0000",
        "title": "Another WP issue",
        "severity": "medium",
        "fixed": "5.1.1",
    }
    forward = load_advisories(json.dumps([*base, wp_extra]))
    reverse = load_advisories(json.dumps([wp_extra, *base]))
    fp = [_cms_fp("WordPress", "5.0.0")]
    titles_fwd = [f.title for f in assess_cms(fp, forward, asset_id="A", url="https://x/").findings]
    titles_rev = [f.title for f in assess_cms(fp, reverse, asset_id="A", url="https://x/").findings]
    assert titles_fwd == titles_rev  # sorted by title, order-independent
    assert len(titles_fwd) == 2


def test_advisory_range_text_variants() -> None:
    assert CmsAdvisory("X", "A", "T", Severity.LOW, "1.0", "2.0").range_text() == ">= 1.0, < 2.0"
    assert CmsAdvisory("X", "A", "T", Severity.LOW, None, None).range_text() == "all versions"
