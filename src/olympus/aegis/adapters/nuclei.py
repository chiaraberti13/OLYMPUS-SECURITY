"""Real nuclei adapter: parses ProjectDiscovery nuclei's JSONL findings stream.

nuclei emits one JSON object per match with ``-jsonl``, which is the only output
mode worth parsing: the human format is prose and changes between releases.

Three behaviours are deliberate. First, nuclei exits 0 whether or not it matched
anything, so "no findings" and "worked" are the same exit code and the parser
must distinguish them by content, never by status. Second, a template's declared
severity is attacker-supplied in the sense that templates are community content:
it is mapped through a fixed table and anything unrecognised becomes INFO rather
than being trusted verbatim. Third, ``-omit-raw`` is passed because nuclei
otherwise embeds the full request and response of every match in its JSONL, and
that stream becomes the run's raw evidence — response bodies routinely carry
session cookies, tokens and personal data.

nuclei is useless without templates, and it finds them through ``$HOME``. Under
the AEGIS sandbox the process runs as an unprivileged user with a different
home, so an operator's ``nuclei-templates`` checkout is invisible and the engine
exits non-zero with "no templates provided for scan". The template directory is
therefore named explicitly through ``AEGIS_NUCLEI_TEMPLATES``, and its absence
produces an error that says what to set rather than a bare exit status.
"""

from __future__ import annotations

import json
import os

from olympus.aegis.base import ParseError, ScannerAdapter
from olympus.aegis.model import ScanRequest
from olympus.aegis.runner import CommandOutput
from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding

#: nuclei's own severity vocabulary, mapped onto the Olympus scale.
_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


#: Where the operator keeps their nuclei-templates checkout. Explicit, because
#: the sandbox user's ``$HOME`` is not the operator's.
TEMPLATES_VARIABLE = "AEGIS_NUCLEI_TEMPLATES"


class NucleiAdapter(ScannerAdapter):
    name = "nuclei"
    binary = "nuclei"
    version_expected = "3.x"
    install = "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

    def templates_path(self) -> str:
        """Return the configured template directory, or an empty string."""
        return os.environ.get(TEMPLATES_VARIABLE, "").strip()

    def build_asset(self, host: str, request: ScanRequest) -> Asset:
        return Asset(
            asset_id=self.asset_id(host),
            asset_type=AssetType.WEB_SERVER,
            hostname=host,
            ip_addresses=list(request.resolved_addresses),
            source=Source.AEGIS,
            tags=["aegis", self.name],
        )

    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        target = request.target if request.target_kind == "url" else f"http://{host}"
        argv = [
            self.binary,
            "-target",
            target,
            "-jsonl",
            "-silent",  # keep the banner and progress bar out of stdout
            "-no-color",
            "-disable-update-check",  # never reach out to GitHub mid-scan
            "-no-interactsh",  # no out-of-band callbacks to a third-party server
            "-omit-raw",  # response bodies carry cookies, tokens and PII
            "-omit-template",  # the base64 template body is noise in evidence
        ]
        templates = self.templates_path()
        if templates:
            argv += ["-templates", templates]
        return argv

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        saw_object = False

        for line in output.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ParseError(f"nuclei emitted an unparseable JSONL line: {exc}") from exc
            if not isinstance(entry, dict):
                continue
            saw_object = True

            info = entry.get("info")
            info = info if isinstance(info, dict) else {}
            template = str(entry.get("template-id") or "unknown-template")
            title = str(info.get("name") or template)
            severity = _SEVERITY.get(str(info.get("severity", "")).lower(), Severity.INFO)
            matched = str(entry.get("matched-at") or entry.get("host") or host)
            tags = info.get("tags")
            tags = tags if isinstance(tags, list) else []

            evidence = [f"template={template}", f"matched-at={matched}"]
            if entry.get("type"):
                evidence.append(f"protocol={entry['type']}")
            if tags:
                evidence.append("tags=" + ",".join(str(tag) for tag in tags[:20]))

            self.add_finding(
                findings,
                Finding(
                    asset_id=asset_id,
                    source=Source.AEGIS,
                    title=f"{title} ({template})",
                    description=str(
                        info.get("description")
                        or f"nuclei template {template} matched on {matched}."
                    ),
                    severity=severity,
                    evidence=evidence,
                ),
                request,
            )

        # nuclei exits 0 with empty stdout for a clean target, so silence is a
        # real result. Output that carried no JSON object at all, however, means
        # the stream was something else entirely and must not read as "clean".
        if output.stdout.strip() and not saw_object:
            raise ParseError("nuclei produced output but no JSONL object")
        return findings

    def missing_templates_hint(self, output: CommandOutput) -> str | None:
        """Return actionable guidance when nuclei refused for want of templates."""
        if "no templates provided" not in (output.stdout + output.stderr):
            return None
        return (
            f"nuclei has no templates. Set {TEMPLATES_VARIABLE} to a nuclei-templates "
            "directory readable by the sandbox user, or run 'nuclei -update-templates' "
            "and point the variable at the result"
        )
