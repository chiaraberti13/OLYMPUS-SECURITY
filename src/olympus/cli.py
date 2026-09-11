"""Unified Olympus command-line entry point.

Every module is exposed as a sub-command, so the whole platform is driven
through a single binary: ``olympus <tool> <command>`` (e.g. ``olympus argus
scan``). ``olympus core`` groups data-contract utilities.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import typer

from olympus import __version__
from olympus.apollo.cli import app as apollo_app
from olympus.argus.cli import app as argus_app
from olympus.argus.pipeline import PipelineDocument, PipelinePreset
from olympus.artemis.cli import app as artemis_app
from olympus.athena.cli import app as athena_app
from olympus.athena.domain.contracts import AssessmentPlan, AssessmentResult
from olympus.core import config as core_config
from olympus.core import policy as core_policy
from olympus.core.execution import redact_mapping
from olympus.core.exit_codes import ExitCode
from olympus.core.models import (
    Alert,
    Asset,
    Event,
    Evidence,
    Finding,
    Incident,
    Observation,
    ScanJob,
    SecurityReport,
)
from olympus.helios.cli import app as helios_app
from olympus.hermes.cli import app as hermes_app
from olympus.integrations.cli import (
    aegis_app,
    register_doctor,
    register_vap_shim,
)
from olympus.metis.cli import app as metis_app
from olympus.metis.models import EngagementPlan, IntelCaseDocument
from olympus.minerva.cli import app as minerva_app
from olympus.proteus.cli import app as proteus_app
from olympus.vulcan.cli import app as vulcan_app

app = typer.Typer(
    help="Olympus — offensive-security platform (Red + Blue).",
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show the Olympus version and exit.",
    ),
) -> None:
    """Olympus — a single binary driving every Red and Blue module."""


core_app = typer.Typer(help="Core data-contract utilities.", no_args_is_help=True)
config_app = typer.Typer(help="Validate and inspect effective configuration.", no_args_is_help=True)
policy_app = typer.Typer(
    help="Inspect and validate the editable execution policy.",
    no_args_is_help=True,
)


@config_app.command("validate")
def validate_config(
    file: Path | None = typer.Option(
        None,
        "--file",
        help="Validate this TOML file instead of automatic discovery.",
    ),
) -> None:
    """Validate configuration and print only redacted effective values."""
    try:
        data, source = core_config.load_config_with_source(file)
        effective = redact_mapping(core_config.effective_config(data))
    except core_config.ConfigError as exc:
        typer.echo(f"olympus: invalid configuration: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        json.dumps(
            {
                "schema_name": "olympus.config-validation",
                "schema_version": "1.0.0",
                "status": "valid",
                "source": str(source) if source is not None else None,
                "environment_overrides": core_config.active_environment_overrides(),
                "effective": effective,
            },
            indent=2,
            sort_keys=True,
        )
    )


_PROFILE_OPTION = typer.Option(
    core_policy.DEFAULT_PROFILE,
    "--profile",
    help="Bounds profile to resolve; named profiles overlay [bounds.default].",
)
_POLICY_FILE_OPTION = typer.Option(
    None,
    "--file",
    help="Use this policy file instead of automatic discovery.",
)


def _load_policy_or_exit(
    file: Path | None,
) -> tuple[core_policy.PolicyRuleset, Path | None]:
    """Load the selected policy, turning any policy failure into exit code 2."""
    try:
        return core_policy.load_policy_with_source(file)
    except core_policy.PolicyError as exc:
        typer.echo(f"olympus: invalid policy: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc


@policy_app.command("show")
def show_policy(
    profile: str = _PROFILE_OPTION,
    file: Path | None = _POLICY_FILE_OPTION,
) -> None:
    """Print the effective, redacted policy for one profile as JSON."""
    ruleset, source = _load_policy_or_exit(file)
    try:
        document = core_policy.effective_document(profile, ruleset, source)
    except core_policy.PolicyError as exc:
        typer.echo(f"olympus: invalid policy: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc
    typer.echo(json.dumps(redact_mapping(document), indent=2, sort_keys=True))


@policy_app.command("validate")
def validate_policy(
    profile: str = _PROFILE_OPTION,
    file: Path | None = _POLICY_FILE_OPTION,
) -> None:
    """Validate the policy document and every bound it resolves. Blocking."""
    ruleset, source = _load_policy_or_exit(file)
    try:
        bounds = core_policy.resolve_bounds(profile, ruleset)
    except core_policy.PolicyError as exc:
        typer.echo(f"olympus: invalid policy: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc
    typer.echo(
        json.dumps(
            redact_mapping(
                {
                    "schema_name": "olympus.policy-validation",
                    "schema_version": core_policy.POLICY_SCHEMA_VERSION,
                    "status": "valid",
                    "source": str(source) if source is not None else None,
                    "profile": profile,
                    "profiles": list(ruleset.profile_names()),
                    "environment_overrides": core_policy.active_environment_overrides(),
                    "bounds": bounds,
                    "lab_enabled": ruleset.lab.enabled,
                }
            ),
            indent=2,
            sort_keys=True,
        )
    )


@policy_app.command("diff")
def diff_policy(
    profile: str = _PROFILE_OPTION,
    file: Path | None = _POLICY_FILE_OPTION,
) -> None:
    """Show only the bounds this policy changes, and which layer changed them."""
    ruleset, source = _load_policy_or_exit(file)
    try:
        changes = core_policy.diff_bounds(profile, ruleset)
    except core_policy.PolicyError as exc:
        typer.echo(f"olympus: invalid policy: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc
    typer.echo(
        json.dumps(
            {
                "schema_name": "olympus.policy-diff",
                "schema_version": core_policy.POLICY_SCHEMA_VERSION,
                "source": str(source) if source is not None else None,
                "profile": profile,
                "changed": changes,
                "unchanged_count": len(core_policy.BOUND_CEILINGS) - len(changes),
            },
            indent=2,
            sort_keys=True,
        )
    )


@policy_app.command("edit")
def edit_policy(
    file: Path | None = _POLICY_FILE_OPTION,
    open_editor: bool = typer.Option(
        True,
        "--open/--no-open",
        help="Launch $VISUAL/$EDITOR after ensuring the file exists.",
    ),
) -> None:
    """Create the policy file from a commented template, then open it.

    An existing file is never overwritten: the command only ensures one exists
    and hands it to the operator's editor.
    """
    target = file if file is not None else Path(core_policy.PROJECT_POLICY_FILE)
    created = False
    if not target.exists():
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(core_policy.TEMPLATE, encoding="utf-8")
        except OSError as exc:
            typer.echo(f"olympus: cannot create policy file {target}: {exc}", err=True)
            raise typer.Exit(code=int(ExitCode.USAGE)) from exc
        created = True
    core_policy.reset_active_policy_cache()
    typer.echo(
        f"olympus: {'created' if created else 'using'} policy file {target}", err=True
    )
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR")
    if open_editor and editor:
        typer.launch(str(target))


@core_app.command("export-schemas")
def export_schemas(
    output_dir: Path | None = typer.Argument(
        None,
        help="Optional directory to write schemas.json into; prints to stdout when omitted.",
    ),
) -> None:
    """Print the JSON Schema of the core models, or write it to a directory."""
    schemas = {
        "olympus.athena.plan": AssessmentPlan.model_json_schema(),
        "olympus.athena.result": AssessmentResult.model_json_schema(),
        "olympus.argus-pipeline-preset": PipelinePreset.model_json_schema(),
        "olympus.argus-pipeline": PipelineDocument.model_json_schema(),
        "olympus.metis-plan": EngagementPlan.model_json_schema(),
        "olympus.metis-case": IntelCaseDocument.model_json_schema(),
        "olympus.asset": Asset.model_json_schema(),
        "olympus.finding": Finding.model_json_schema(),
        "olympus.event": Event.model_json_schema(),
        "olympus.evidence": Evidence.model_json_schema(),
        "olympus.alert": Alert.model_json_schema(),
        "olympus.incident": Incident.model_json_schema(),
        "olympus.observation": Observation.model_json_schema(),
        "olympus.scan-job": ScanJob.model_json_schema(),
        "olympus.security-report": SecurityReport.model_json_schema(),
    }
    payload = json.dumps(schemas, indent=2, sort_keys=True)
    if output_dir is None:
        typer.echo(payload)
        return
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / "schemas.json"
    destination.write_text(payload, encoding="utf-8")
    typer.echo(f"olympus: wrote core schemas to {destination}", err=True)


@core_app.command("sbom")
def export_sbom(
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the SBOM here instead of stdout.",
    ),
    extra: list[str] = typer.Option(
        [],
        "--extra",
        help="Include an optional-dependency extra (e.g. --extra aegis). Repeatable.",
    ),
    reproducible: bool = typer.Option(
        False,
        "--reproducible",
        help="Omit the timestamp and serial number for a byte-stable document.",
    ),
) -> None:
    """Emit a CycloneDX SBOM of the installed Olympus runtime closure.

    Generated from ``importlib.metadata`` — no external tool — so it always
    describes the packages this interpreter would load. ``--extra`` widens the
    closure to an optional-dependency group; ``--reproducible`` drops the
    timestamp and serial so two runs are byte-for-byte identical.
    """
    import datetime
    import uuid

    from olympus.core import sbom as sbom_module

    timestamp: str | None = None
    serial: str | None = None
    if not reproducible:
        timestamp = datetime.datetime.now(datetime.UTC).isoformat()
        serial = f"urn:uuid:{uuid.uuid4()}"
    document = sbom_module.render_sbom(
        extras=frozenset(extra), timestamp=timestamp, serial_number=serial
    )
    payload = json.dumps(document, indent=2, sort_keys=True)
    if output is None:
        typer.echo(payload)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(payload + "\n", encoding="utf-8")
    typer.echo(f"olympus: wrote SBOM ({len(document['components'])} components) to {output}",
               err=True)


@core_app.command("lock")
def export_lockfile(
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the constraints here instead of stdout.",
    ),
    extra: list[str] = typer.Option(
        [],
        "--extra",
        help="Include an optional-dependency extra (e.g. --extra aegis). Repeatable.",
    ),
) -> None:
    """Emit a hash-pinned ``pip --require-hashes`` constraints file.

    Pins every package in the runtime closure to its installed version *and* to
    the SHA-256 digests PyPI publishes for that release, so a substituted
    artifact is rejected at install time. Hashes are fetched from the PyPI JSON
    API. Install with ``pip install --require-hashes -r constraints.txt``.
    """
    from olympus.core import lockfile

    try:
        document = lockfile.generate_lockfile(extras=frozenset(extra))
    except lockfile.LockfileError as exc:
        typer.echo(f"olympus: cannot generate lockfile: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.FAILED)) from exc
    if output is None:
        typer.echo(document, nl=False)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document, encoding="utf-8")
    typer.echo(f"olympus: wrote hash-pinned constraints to {output}", err=True)


@core_app.command("keygen")
def signing_keygen(
    private: Path = typer.Option(..., "--private", help="Owner-only Ed25519 private key output."),
    public: Path = typer.Option(..., "--public", help="Ed25519 public key output (distributable)."),
) -> None:
    """Generate an Ed25519 keypair for signing artifacts (provenance)."""
    from olympus.core.fileio import atomic_write_text
    from olympus.core.signing import generate_keypair

    try:
        private_pem, public_pem = generate_keypair()
        atomic_write_text(private, private_pem, mode=0o600)
        atomic_write_text(public, public_pem, mode=0o644)
    except OSError as exc:
        typer.echo(f"olympus: keygen error: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.FAILED)) from exc
    typer.echo(f"olympus: wrote private key {private} (0600) and public key {public}", err=True)


@core_app.command("sign")
def signing_sign(
    artifact: Path = typer.Argument(..., help="File to sign (ledger, evidence, SBOM, report...)."),
    key: Path = typer.Option(..., "--key", help="Ed25519 private key PEM."),
    output: Path = typer.Option(
        ..., "--output", "-o", help="Signature envelope output (owner-only)."
    ),
    max_bytes: int = typer.Option(500_000_000, "--max-bytes"),
) -> None:
    """Produce a detached Ed25519 signature so a third party can verify provenance."""
    from olympus.core.fileio import atomic_write_text, read_regular_bytes, read_regular_text
    from olympus.core.signing import SigningError, sign

    try:
        data = read_regular_bytes(artifact, max_bytes=max_bytes, label="artifact")
        private_pem = read_regular_text(key, max_bytes=1_000_000, label="private key")
        envelope = sign(data, private_pem)
        atomic_write_text(output, envelope, mode=0o600)
    except (SigningError, OSError, ValueError) as exc:
        typer.echo(f"olympus: sign error: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc
    typer.echo(f"olympus: signed {artifact} -> {output}", err=True)


@core_app.command("verify")
def signing_verify(
    artifact: Path = typer.Argument(..., help="File whose signature to check."),
    signature: Path = typer.Argument(..., help="Signature envelope from `core sign`."),
    pubkey: Path = typer.Option(..., "--pubkey", help="TRUSTED Ed25519 public key PEM to pin."),
    max_bytes: int = typer.Option(500_000_000, "--max-bytes"),
) -> None:
    """Verify a detached Ed25519 signature against a trusted public key.

    Exits 0 if the signature is valid and made by the trusted key, 1 if the
    signature does not match the data, 2 on any error (including a signature made
    by a different key).
    """
    from olympus.core.fileio import read_regular_bytes, read_regular_text
    from olympus.core.signing import SigningError, verify

    try:
        data = read_regular_bytes(artifact, max_bytes=max_bytes, label="artifact")
        envelope = read_regular_text(signature, max_bytes=1_000_000, label="signature")
        public_pem = read_regular_text(pubkey, max_bytes=1_000_000, label="public key")
        valid = verify(data, envelope, public_pem=public_pem)
    except (SigningError, OSError, ValueError) as exc:
        typer.echo(f"olympus: verify error: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc
    if valid:
        typer.echo(f"olympus: signature VALID for {artifact} (trusted key)")
    else:
        typer.echo(f"olympus: signature INVALID for {artifact}", err=True)
        raise typer.Exit(code=1)


app.add_typer(core_app, name="core")
app.add_typer(config_app, name="config")
app.add_typer(policy_app, name="policy")
app.add_typer(argus_app, name="argus")
app.add_typer(athena_app, name="athena")
app.add_typer(helios_app, name="helios")
app.add_typer(artemis_app, name="artemis")
app.add_typer(proteus_app, name="proteus")
app.add_typer(hermes_app, name="hermes")
app.add_typer(apollo_app, name="apollo")
app.add_typer(minerva_app, name="minerva")
app.add_typer(vulcan_app, name="vulcan")
app.add_typer(metis_app, name="metis")
app.add_typer(aegis_app, name="aegis")
register_vap_shim(app)  # deprecated 'olympus vap' -> forwards to 'olympus aegis'
register_doctor(app)  # 'olympus doctor'


@app.command()
def version() -> None:
    """Print the Olympus version."""
    typer.echo(__version__)


@app.command("ui")
def terminal_ui() -> None:
    """Open the keyboard-first interface for every Olympus tool."""
    from typer.main import get_command

    from olympus.tui import OlympusTui

    root = get_command(app)
    if not isinstance(root, typer.core.TyperGroup):
        raise RuntimeError("Olympus root command is not a command group")
    OlympusTui(root).run()


def main() -> None:  # pragma: no cover
    """Console-script entry point."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
