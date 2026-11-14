"""The API reference is generated from the live OpenAPI schema and never drifts (DOCS-2).

``docs/api-reference.md`` is produced by ``olympus.api_reference.render_document``
from the real Themis application. These tests pin that the committed doc is current
(the drift gate), that the render is deterministic, and that real endpoints with
their versioned contracts actually appear — so the page cannot fall behind the API.
"""

from __future__ import annotations

from pathlib import Path

from olympus.api_reference import (
    BLOCK_BEGIN,
    BLOCK_END,
    openapi_document,
    render_api_reference,
    render_document,
)

_DOC = Path(__file__).resolve().parents[2] / "docs" / "api-reference.md"


def test_committed_reference_is_current() -> None:
    assert _DOC.read_text(encoding="utf-8") == render_document(), (
        "docs/api-reference.md is stale; run "
        "`python scripts/generate_api_reference.py` to regenerate it."
    )


def test_render_is_deterministic() -> None:
    document = openapi_document()
    # Same schema in -> byte-identical output, regardless of how many times built.
    assert render_document(document) == render_document(document)


def test_generated_block_is_marker_delimited() -> None:
    document = render_document()
    assert BLOCK_BEGIN in document and BLOCK_END in document
    assert document.index(BLOCK_BEGIN) < document.index(BLOCK_END)


def test_real_endpoints_and_contracts_are_documented() -> None:
    body = render_api_reference(openapi_document())
    # An endpoint from each of several modules, with its versioned contract.
    assert "### `POST /api/v1/hermes/scan-text`" in body
    assert "`olympus.hermes-secret-scan`" in body
    assert "### `POST /api/v1/helios/identify-service`" in body
    assert "### `POST /api/v1/proteus/validate-campaign`" in body
    assert "### `POST /api/v1/vulcan/correlate`" in body
    assert "### `GET /api/v1/capabilities`" in body


def test_operations_are_sorted_by_path_then_method() -> None:
    headings = [line for line in render_api_reference().splitlines() if line.startswith("### ")]

    # Each heading is "### `METHOD /path`"; the generator sorts by path then method,
    # so a regenerated page is byte-stable.
    def _pair(line: str) -> tuple[str, str]:
        inner = line[len("### `") : -1]  # strip '### `' and the trailing backtick
        method, path = inner.split(" ", 1)
        return path, method

    pairs = [_pair(line) for line in headings]
    assert pairs == sorted(pairs)
