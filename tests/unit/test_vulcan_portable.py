"""Portable NDJSON import/export for findings and assets, and its CLI (ROADMAP ``WEB-J``).

These tests pin the lossless round-trip with the JSON bundles the loaders consume,
the deterministic wire format, the strict all-or-nothing import, and the CLI exit
codes.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import AssetType, Severity, Source
from olympus.core.exit_codes import ExitCode
from olympus.core.models import Asset, Finding
from olympus.vulcan.aggregate import load_assets, load_findings
from olympus.vulcan.portable import (
    PortabilityError,
    export_assets,
    export_findings,
    import_assets,
    import_findings,
)

runner = CliRunner()


def _finding(fid: str, title: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        finding_id=fid, asset_id="AST-1", source=Source.ARTEMIS, title=title, severity=severity
    )


def _asset(aid: str, hostname: str) -> Asset:
    return Asset(asset_id=aid, asset_type=AssetType.HOST, hostname=hostname, source=Source.ARGUS)


def test_findings_export_is_deterministic_and_sorted() -> None:
    a = _finding("FND-2026-00001", "XSS")
    b = _finding("FND-2026-00002", "SQLi", Severity.CRITICAL)
    first = export_findings([b, a])
    assert first == export_findings([a, b])
    lines = first.splitlines()
    assert json.loads(lines[0])["finding_id"] == "FND-2026-00001"


def test_findings_round_trip_is_lossless() -> None:
    findings = [_finding("FND-2026-00001", "XSS"), _finding("FND-2026-00002", "SQLi")]
    restored = import_findings(export_findings(findings))
    assert sorted(f.model_dump_json() for f in restored) == sorted(
        f.model_dump_json() for f in findings
    )


def test_assets_round_trip_is_lossless() -> None:
    assets = [_asset("AST-1", "a.example"), _asset("AST-2", "b.example")]
    restored = import_assets(export_assets(assets))
    assert sorted(a.hostname or "" for a in restored) == ["a.example", "b.example"]


def test_import_is_all_or_nothing_on_a_bad_line() -> None:
    good = export_findings([_finding("FND-2026-00001", "XSS")]).strip()
    try:
        import_findings(good + '\n{"schema_name": "olympus.asset", "schema_version": "1.0.0"}')
    except PortabilityError as exc:
        assert "line 2" in str(exc)
    else:  # pragma: no cover - the call must raise
        raise AssertionError("expected PortabilityError")


def test_import_rejects_an_oversize_line() -> None:
    try:
        import_findings(export_findings([_finding("FND-2026-00001", "XSS")]), max_line_bytes=10)
    except PortabilityError as exc:
        assert "byte limit" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected PortabilityError")


def _bundle(path: Path, records: list[dict[str, object]]) -> Path:
    path.write_text(json.dumps(records), encoding="utf-8")
    return path


def test_cli_findings_bundle_ndjson_round_trip(tmp_path: Path) -> None:
    findings = [_finding("FND-2026-00001", "XSS"), _finding("FND-2026-00002", "SQLi")]
    bundle = _bundle(tmp_path / "in.json", [json.loads(f.model_dump_json()) for f in findings])
    ndjson = tmp_path / "out.ndjson"
    restored = tmp_path / "restored.json"

    exported = runner.invoke(
        app, ["vulcan", "export", "--kind", "findings", "-i", str(bundle), "-o", str(ndjson)]
    )
    assert exported.exit_code == 0, exported.output
    assert json.loads(exported.output)["exported"] == 2

    imported = runner.invoke(
        app, ["vulcan", "import", "--kind", "findings", "-i", str(ndjson), "-o", str(restored)]
    )
    assert imported.exit_code == 0, imported.output
    back = load_findings([restored])
    assert sorted(f.model_dump_json() for f in back) == sorted(
        f.model_dump_json() for f in findings
    )


def test_cli_assets_round_trip(tmp_path: Path) -> None:
    assets = [_asset("AST-1", "a.example")]
    bundle = _bundle(tmp_path / "in.json", [json.loads(a.model_dump_json()) for a in assets])
    ndjson = tmp_path / "out.ndjson"
    restored = tmp_path / "restored.json"
    assert (
        runner.invoke(
            app, ["vulcan", "export", "--kind", "assets", "-i", str(bundle), "-o", str(ndjson)]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app, ["vulcan", "import", "--kind", "assets", "-i", str(ndjson), "-o", str(restored)]
        ).exit_code
        == 0
    )
    assert load_assets([restored])[0].hostname == "a.example"


def test_cli_rejects_unknown_kind(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path / "in.json", [])
    result = runner.invoke(
        app,
        ["vulcan", "export", "--kind", "bogus", "-i", str(bundle), "-o", str(tmp_path / "o")],
    )
    assert result.exit_code == ExitCode.USAGE


def test_cli_import_rejects_malformed_ndjson_without_writing(tmp_path: Path) -> None:
    bad = tmp_path / "bad.ndjson"
    bad.write_text("{not json}\n", encoding="utf-8")
    out = tmp_path / "out.json"
    result = runner.invoke(
        app, ["vulcan", "import", "--kind", "findings", "-i", str(bad), "-o", str(out)]
    )
    assert result.exit_code == ExitCode.USAGE
    assert not out.exists()
