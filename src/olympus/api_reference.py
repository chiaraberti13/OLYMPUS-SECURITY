"""Generate the HTTP API reference from the live OpenAPI schema (ROADMAP ``DOCS-2``).

The API surface is defined once, in the typed FastAPI endpoints and their
request/response contract models. Hand-writing an API reference beside them
guarantees drift. This module builds the real application, reads its OpenAPI
schema — the single source of truth — and renders a deterministic Markdown
reference, so the documentation is derived from the code and a stale page fails
the drift gate (``scripts/generate_api_reference.py --check``) instead of
misleading a reader.

For every operation it records the method and path, the one-line purpose (from
the endpoint docstring), its tags and, crucially, the **versioned contract**
behind the request and the 200 response — resolved from each schema's
``schema_name``/``schema_version`` constants where present — so a client sees
exactly which ``olympus.*`` contract a call accepts and returns.

Pure except for building the app in a throwaway temporary directory; it never
executes a scan, opens a durable store or touches the network. The output is
deterministic — operations are sorted by path then method, so regenerating on an
unchanged surface yields byte-identical output.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

#: Markers delimiting the generated block, mirroring ``cli_reference`` so the same
#: drift-gate discipline applies.
BLOCK_BEGIN = "<!-- GENERATED:api-reference START -->"
BLOCK_END = "<!-- GENERATED:api-reference END -->"

_DOC_HEADER = """# HTTP API reference

Every versioned Olympus HTTP endpoint, generated from the live OpenAPI schema of
the Themis application (`olympus.themis.api:create_app`) — the single source of
truth, so this page cannot drift from the real API. Each operation names the
versioned request/response contract it accepts and returns. Authentication uses
an API key or bearer token; the per-endpoint scope is documented in
`docs/web.md`. Do not edit the generated block by hand; run
`python scripts/generate_api_reference.py` (or `--check` in CI) instead.
"""

_HTTP_METHODS = ("get", "post", "put", "patch", "delete")


def openapi_document() -> dict[str, Any]:
    """Return the live OpenAPI schema of the Themis application.

    The app is built in a throwaway temporary directory (a scope directory and an
    unused SQLite path) purely so FastAPI can assemble the schema; nothing is
    executed and no durable state is created.
    """
    from olympus.themis.api import ApiSettings, create_app

    with tempfile.TemporaryDirectory(prefix="olympus-apiref-") as tmp:
        root = Path(tmp)
        scope_directory = root / "scopes"
        scope_directory.mkdir()
        app = create_app(
            ApiSettings(
                database=root / "themis.sqlite3",
                scope_directory=scope_directory,
                api_key="api-reference-key-32-characters!",
            )
        )
        schema: dict[str, Any] = app.openapi()
        return schema


def _cell(text: str) -> str:
    """Make free text safe for a single Markdown table cell (single line)."""
    return text.replace("|", r"\|").replace("\n", " ").strip()


def _first_sentence(description: str) -> str:
    """Return the first non-empty line of an endpoint docstring, collapsed."""
    for line in description.splitlines():
        stripped = line.strip()
        if stripped:
            return " ".join(stripped.split())
    return ""


def _contract_of(schema: dict[str, Any] | None, components: dict[str, Any]) -> str:
    """Name the versioned contract behind a request/response schema reference.

    Resolves a ``$ref`` to its component and returns ``olympus.<name> <version>``
    when the model declares ``schema_name``/``schema_version`` constants, else the
    component's title, else ``—``. A schema with no ``$ref`` (a primitive or inline
    object) has no named contract.
    """
    if not schema:
        return "—"
    ref = schema.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/components/schemas/"):
        return "—"
    name = ref.rsplit("/", 1)[-1]
    component = components.get(name, {})
    properties = component.get("properties", {})
    schema_name = properties.get("schema_name", {}).get("const")
    if isinstance(schema_name, str):
        version = properties.get("schema_version", {}).get("const")
        return f"`{schema_name}`" + (f" `{version}`" if isinstance(version, str) else "")
    title = component.get("title")
    return f"`{title}`" if isinstance(title, str) else "—"


def _request_contract(operation: dict[str, Any], components: dict[str, Any]) -> str:
    body = operation.get("requestBody")
    if not isinstance(body, dict):
        return "—"
    schema = body.get("content", {}).get("application/json", {}).get("schema")
    return _contract_of(schema, components)


def _response_contract(operation: dict[str, Any], components: dict[str, Any]) -> str:
    responses = operation.get("responses", {})
    for code in ("200", "201"):
        success = responses.get(code)
        if isinstance(success, dict):
            schema = success.get("content", {}).get("application/json", {}).get("schema")
            resolved = _contract_of(schema, components)
            if resolved != "—":
                return resolved
    return "—"


def render_api_reference(document: dict[str, Any] | None = None) -> str:
    """Return the deterministic Markdown body for every documented API operation."""
    schema = document if document is not None else openapi_document()
    components = schema.get("components", {}).get("schemas", {})
    paths = schema.get("paths", {})
    out: list[str] = []
    for path in sorted(paths):
        for method in _HTTP_METHODS:
            operation = paths[path].get(method)
            if not isinstance(operation, dict):
                continue
            out.append(f"### `{method.upper()} {path}`")
            out.append("")
            purpose = _first_sentence(operation.get("description", "") or "")
            if purpose:
                out.append(_cell(purpose))
                out.append("")
            tags = ", ".join(operation.get("tags", []) or []) or "—"
            request = _request_contract(operation, components)
            response = _response_contract(operation, components)
            out.append("| Tags | Request contract | Response contract |")
            out.append("| --- | --- | --- |")
            out.append(f"| {_cell(tags)} | {request} | {response} |")
            out.append("")
    return "\n".join(out).rstrip() + "\n"


def render_api_reference_section(document: dict[str, Any] | None = None) -> str:
    """Return the marker-delimited generated block."""
    return f"{BLOCK_BEGIN}\n{render_api_reference(document)}{BLOCK_END}\n"


def render_document(document: dict[str, Any] | None = None) -> str:
    """Return the full ``docs/api-reference.md`` content (header + generated block)."""
    return f"{_DOC_HEADER}\n{render_api_reference_section(document)}"


__all__ = [
    "BLOCK_BEGIN",
    "BLOCK_END",
    "openapi_document",
    "render_api_reference",
    "render_api_reference_section",
    "render_document",
]
