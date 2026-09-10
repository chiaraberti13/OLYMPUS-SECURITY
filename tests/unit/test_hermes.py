"""Tests for Hermes detection, history scanning, SARIF and demo UX."""

import json
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.execution import CancellationRequested, CancellationToken, ExecutionPolicy
from olympus.hermes.application import SecretScanRequest, SecretScanService
from olympus.hermes.sarif import to_sarif
from olympus.hermes.scanner import (
    ALLOWLIST_SCHEMA_NAME,
    ALLOWLIST_SCHEMA_VERSION,
    Allowlist,
    ScanLimitError,
    SecretFinding,
    load_allowlist,
    load_baseline,
    scan_git_history,
    scan_path,
    scan_paths_bounded,
    scan_text,
    write_baseline,
)

runner = CliRunner()
SYNTHETIC_KEY = "AKIA" + "OLYMPUSDEMO00000"


def _git_executable() -> str:
    executable = shutil.which("git")
    assert executable is not None
    return executable


GIT = _git_executable()


def _policy() -> ExecutionPolicy:
    return ExecutionPolicy(timeout_seconds=30.0, deadline_seconds=60.0)


def test_regex_masks_known_secret_and_avoids_false_positive() -> None:
    findings = scan_text(f"key={SYNTHETIC_KEY}\nrepeat={SYNTHETIC_KEY}\nordinary=short", "demo.env")

    assert len(findings) == 1
    assert findings[0].rule == "aws-access-key"
    assert SYNTHETIC_KEY not in findings[0].masked
    assert findings[0].line == 1


def test_entropy_threshold_is_configurable() -> None:
    candidate = "aB3dE5gH7jK9mN2pQ4sT6vX8"

    assert scan_text(candidate, "demo", entropy_threshold=3.0)
    assert not scan_text(candidate, "demo", entropy_threshold=8.0)


def test_scan_path_skips_binary_data(tmp_path: Path) -> None:
    (tmp_path / "safe.txt").write_text("ordinary text", encoding="utf-8")
    (tmp_path / "binary").write_bytes(b"\xff\xfe")

    assert scan_path(tmp_path) == []


def test_scan_rejects_missing_direct_symlink_and_oversized_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        scan_path(tmp_path / "missing")

    target = tmp_path / "target.txt"
    target.write_text("safe", encoding="utf-8")
    symlink = tmp_path / "link.txt"
    symlink.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        scan_path(symlink)

    target.write_text("too large", encoding="utf-8")
    with pytest.raises(ScanLimitError, match="byte limit"):
        scan_paths_bounded([target], max_file_bytes=4, policy=_policy())

    (tmp_path / "second.txt").write_text("safe", encoding="utf-8")
    with pytest.raises(ScanLimitError, match="entry limit"):
        scan_paths_bounded([tmp_path], max_files=1, policy=_policy())


def test_scan_excludes_existing_output_and_baseline_artifacts(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    output = tmp_path / "results.sarif"
    source.write_text("safe", encoding="utf-8")
    output.write_text(SYNTHETIC_KEY, encoding="utf-8")

    result = scan_paths_bounded([tmp_path], excluded_paths=(output,), policy=_policy())

    assert result.findings == ()
    assert any(item.path == str(output) for item in result.ignored_files)


def test_sarif_contains_mask_only() -> None:
    finding = scan_text(SYNTHETIC_KEY, "demo.env")[0]
    sarif = to_sarif([finding])
    serialized = json.dumps(sarif)

    assert sarif["version"] == "2.1.0"
    assert SYNTHETIC_KEY not in serialized
    assert sarif["runs"][0]["results"][0]["ruleId"] == "aws-access-key"


def test_git_history_scan_finds_removed_synthetic_secret(tmp_path: Path) -> None:
    subprocess.run([GIT, "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run([GIT, "config", "user.email", "demo@example.com"], cwd=tmp_path, check=True)
    subprocess.run([GIT, "config", "user.name", "Olympus Demo"], cwd=tmp_path, check=True)
    secret_file = tmp_path / "demo.env"
    secret_file.write_text(SYNTHETIC_KEY, encoding="utf-8")
    subprocess.run([GIT, "add", "demo.env"], cwd=tmp_path, check=True)
    subprocess.run([GIT, "commit", "-qm", "synthetic fixture"], cwd=tmp_path, check=True)
    secret_file.write_text("removed", encoding="utf-8")
    subprocess.run([GIT, "commit", "-qam", "remove fixture"], cwd=tmp_path, check=True)

    findings = scan_git_history(tmp_path, policy=_policy())

    assert any(finding.rule == "aws-access-key" for finding in findings)
    assert len(findings) == 1
    assert findings[0].path.endswith("/demo.env")
    assert "git-history/" in findings[0].path
    with pytest.raises(ScanLimitError, match="history exceeds"):
        scan_git_history(tmp_path, policy=_policy(), max_history_bytes=1)


def test_application_bounds_history_and_observes_cancellation(tmp_path: Path) -> None:
    source = tmp_path / "safe.txt"
    source.write_text("safe", encoding="utf-8")
    calls: list[tuple[Path, float, int, int]] = []

    def history(
        repository: Path,
        threshold: float,
        *,
        policy: ExecutionPolicy,
        cancellation: object,
        max_history_bytes: int,
        max_commits: int,
        allowlist: object = None,
    ) -> list[SecretFinding]:
        del cancellation, allowlist
        calls.append((repository, policy.timeout_seconds, max_history_bytes, max_commits))
        return []

    outcome = SecretScanService(history_scanner=history).run(
        SecretScanRequest(
            paths=(tmp_path,),
            history=True,
            timeout_seconds=2.0,
            max_history_bytes=1234,
            max_commits=7,
        )
    )
    assert outcome.history_scanned is True
    assert calls == [(tmp_path, 2.0, 1234, 7)]

    token = CancellationToken()
    token.cancel()
    with pytest.raises(CancellationRequested):
        SecretScanService(cancellation=token).run(SecretScanRequest(paths=(source,)))


def test_hermes_scan_writes_sarif_and_signals_findings(tmp_path: Path) -> None:
    source = tmp_path / "demo.env"
    output = tmp_path / "results.sarif"
    source.write_text(SYNTHETIC_KEY, encoding="utf-8")

    result = runner.invoke(
        app,
        ["hermes", "scan", str(source), "--output", str(output)],
    )

    assert result.exit_code == 1
    assert output.exists()
    assert SYNTHETIC_KEY not in output.read_text(encoding="utf-8")


def test_baseline_suppresses_known_findings(tmp_path: Path) -> None:
    from olympus.hermes.scanner import apply_baseline

    findings = scan_text(SYNTHETIC_KEY, "demo.env")
    assert findings
    baseline_path = tmp_path / "baseline.json"
    write_baseline(findings, baseline_path)
    baseline = load_baseline(baseline_path)
    assert apply_baseline(findings, baseline) == []  # all accepted -> none reported
    document = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert document["schema_name"] == "olympus.hermes-baseline"
    assert document["schema_version"] == "1.0.0"
    assert stat.S_IMODE(baseline_path.stat().st_mode) == 0o600


def test_baseline_rejects_unknown_fields_and_invalid_fingerprints(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text(
        json.dumps(
            {
                "schema_name": "olympus.hermes-baseline",
                "schema_version": "1.0.0",
                "fingerprints": ["not-a-sha256"],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="SHA-256"):
        load_baseline(path)


def test_cli_scan_with_baseline_exits_zero(tmp_path: Path) -> None:
    source = tmp_path / "demo.env"
    source.write_text(SYNTHETIC_KEY, encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    out = tmp_path / "r.sarif"
    # First: record the finding as a baseline.
    first = runner.invoke(
        app,
        ["hermes", "scan", str(source), "--output", str(out), "--write-baseline", str(baseline)],
    )
    assert first.exit_code == 1  # finding present on first run
    # Second: with the baseline applied, the known finding is suppressed.
    second = runner.invoke(
        app, ["hermes", "scan", str(source), "--output", str(out), "--baseline", str(baseline)]
    )
    assert second.exit_code == 0, second.output
    assert "0 potential secret" in second.stdout


def test_cli_missing_path_and_partial_directory_are_not_clean(tmp_path: Path) -> None:
    missing = runner.invoke(
        app, ["hermes", "scan", str(tmp_path / "missing"), "--output", str(tmp_path / "m.sarif")]
    )
    assert missing.exit_code == 2
    assert "does not exist" in missing.output

    source = tmp_path / "large.txt"
    source.write_text("larger-than-five", encoding="utf-8")
    output = tmp_path / "partial.sarif"
    partial = runner.invoke(
        app,
        [
            "hermes",
            "scan",
            str(tmp_path),
            "--max-file-bytes",
            "5",
            "--output",
            str(output),
        ],
    )
    assert partial.exit_code == 2
    assert "partial scan" in partial.output
    assert output.exists()


# --- Allowlist: suppress false positives by shape, not by fingerprint (§2) --- #


def _write_allowlist(
    path: Path, *, path_patterns: list[str], value_patterns: list[str]
) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_name": ALLOWLIST_SCHEMA_NAME,
                "schema_version": ALLOWLIST_SCHEMA_VERSION,
                "path_patterns": path_patterns,
                "value_patterns": value_patterns,
            }
        ),
        encoding="utf-8",
    )


def test_allowlist_suppresses_a_matching_value_pattern() -> None:
    text = f'aws_key = "{SYNTHETIC_KEY}"'
    assert scan_text(text, "config.py")  # flagged without an allowlist
    allowlist = Allowlist(value_patterns=(re.compile("OLYMPUSDEMO"),))
    assert scan_text(text, "config.py", allowlist=allowlist) == []


def test_allowlist_suppresses_a_matching_path_glob(tmp_path: Path) -> None:
    fixture = tmp_path / "tests" / "fixtures" / "sample.txt"
    fixture.parent.mkdir(parents=True)
    fixture.write_text(f"token={SYNTHETIC_KEY}", encoding="utf-8")

    allowlist = Allowlist(path_patterns=("*/fixtures/*",))
    result = scan_paths_bounded(
        [fixture], policy=_policy(), allowlist=allowlist
    )
    assert result.findings == ()
    assert result.scanned_files == 1  # scanned, but suppressed by shape


def test_allowlist_leaves_an_unmatched_secret_flagged() -> None:
    text = f'aws_key = "{SYNTHETIC_KEY}"'
    allowlist = Allowlist(value_patterns=(re.compile("SOMETHING_ELSE"),))
    assert len(scan_text(text, "config.py", allowlist=allowlist)) == 1


def test_load_allowlist_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    _write_allowlist(path, path_patterns=["*/fixtures/*"], value_patterns=["EXAMPLE$"])
    allowlist = load_allowlist(path)
    assert allowlist.path_patterns == ("*/fixtures/*",)
    assert allowlist.allows("a/fixtures/b.txt", "irrelevant") is True
    assert allowlist.allows("src/app.py", "MY_EXAMPLE") is True
    assert allowlist.allows("src/app.py", "real-secret") is False


def test_load_allowlist_rejects_an_invalid_regex(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    _write_allowlist(path, path_patterns=[], value_patterns=["("])  # unbalanced
    with pytest.raises(ValueError, match="not a valid regex"):
        load_allowlist(path)


def test_load_allowlist_rejects_extra_keys(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    path.write_text(
        json.dumps(
            {
                "schema_name": ALLOWLIST_SCHEMA_NAME,
                "schema_version": ALLOWLIST_SCHEMA_VERSION,
                "path_patterns": [],
                "value_patterns": [],
                "unexpected": True,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="must define exactly"):
        load_allowlist(path)


def test_scan_command_applies_the_allowlist(tmp_path: Path) -> None:
    source = tmp_path / "config.py"
    source.write_text(f'aws_key = "{SYNTHETIC_KEY}"', encoding="utf-8")
    output = tmp_path / "results.sarif"
    allowlist = tmp_path / "allowlist.json"
    _write_allowlist(allowlist, path_patterns=[], value_patterns=["OLYMPUSDEMO"])

    without = runner.invoke(app, ["hermes", "scan", str(source), "--output", str(output)])
    assert without.exit_code == 1  # a finding without the allowlist

    with_allowlist = runner.invoke(
        app,
        ["hermes", "scan", str(source), "--output", str(output), "--allowlist", str(allowlist)],
    )
    assert with_allowlist.exit_code == 0, with_allowlist.output
    assert "0 potential secret(s)" in with_allowlist.output


# --- pre-commit hook command (roadmap §2 Hermes) ----------------------------- #


def _git_repo(tmp_path: Path) -> Path:
    subprocess.run([GIT, "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run([GIT, "config", "user.email", "d@example.com"], cwd=tmp_path, check=True)
    subprocess.run([GIT, "config", "user.name", "Demo"], cwd=tmp_path, check=True)
    return tmp_path


def test_pre_commit_scans_given_paths_and_blocks_on_a_secret(tmp_path: Path) -> None:
    leaky = tmp_path / "config.py"
    leaky.write_text(f'aws = "{SYNTHETIC_KEY}"', encoding="utf-8")
    result = runner.invoke(app, ["hermes", "pre-commit", str(leaky)])
    assert result.exit_code == 1
    assert "commit blocked" in result.output
    assert SYNTHETIC_KEY not in result.output  # masked


def test_pre_commit_is_clean_for_a_safe_file(tmp_path: Path) -> None:
    safe = tmp_path / "notes.txt"
    safe.write_text("nothing secret here", encoding="utf-8")
    result = runner.invoke(app, ["hermes", "pre-commit", str(safe)])
    assert result.exit_code == 0
    assert "clean" in result.output


def test_pre_commit_scans_the_git_index_when_no_paths_given(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    leaky = repo / "secret.env"
    leaky.write_text(SYNTHETIC_KEY, encoding="utf-8")
    subprocess.run([GIT, "add", "secret.env"], cwd=repo, check=True)

    # CliRunner has no cwd argument, so scan the staged index from inside the repo.
    import os

    cwd = Path.cwd()
    try:
        os.chdir(repo)
        staged = runner.invoke(app, ["hermes", "pre-commit"])
    finally:
        os.chdir(cwd)
    assert staged.exit_code == 1
    assert "secret.env" in staged.output


def test_pre_commit_allowlist_suppresses_a_staged_secret(tmp_path: Path) -> None:
    leaky = tmp_path / "config.py"
    leaky.write_text(f'aws = "{SYNTHETIC_KEY}"', encoding="utf-8")
    allowlist = tmp_path / "allow.json"
    allowlist.write_text(
        json.dumps(
            {
                "schema_name": "olympus.hermes-allowlist",
                "schema_version": "1.0.0",
                "path_patterns": [],
                "value_patterns": ["OLYMPUSDEMO"],
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(
        app, ["hermes", "pre-commit", str(leaky), "--allowlist", str(allowlist)]
    )
    assert result.exit_code == 0, result.output
