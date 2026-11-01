"""Real wpscan adapter: parses WPScan's ``--format json`` WordPress report.

WPScan emits a single JSON object describing the scanned WordPress site: the core
``version`` block, the ``main_theme``, every entry under ``plugins`` and a list of
``interesting_findings``. Each of those carries a ``vulnerabilities`` array of
disclosed issues. The parser collects those vulnerabilities (never inventing a
severity: a disclosed WordPress vulnerability without a score is surfaced at a
conservative MEDIUM, with its references and fixed-in version preserved as
evidence) and the interesting findings as INFO disclosures.

The WPScan vulnerability-database API token is a secret: it is read only from the
environment (``THEMIS_WPSCAN_API_TOKEN``, legacy ``AEGIS_WPSCAN_API_TOKEN``) at
argv-build time and never stored, defaulted or committed. Without it WPScan still
runs; it simply cannot enrich from the vulnerability database.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding
from olympus.themis.base import ParseError, ScannerAdapter, check_json_depth
from olympus.themis.config import get as get_env
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput


class WpscanAdapter(ScannerAdapter):
    name = "wpscan"
    binary = "wpscan"
    version_expected = "3.8.x"
    install = "gem install wpscan (requires a working Ruby environment)"
    # WPScan exits 5 when it completes and vulnerabilities were detected; that is a
    # successful scan, not a failure, so both 0 and 5 are accepted.
    success_exit_codes = frozenset({0, 5})

    def build_asset(self, host: str, request: ScanRequest) -> Asset:
        return Asset(
            asset_id=self.asset_id(host),
            asset_type=AssetType.WEB_SERVER,
            hostname=host,
            ip_addresses=list(request.resolved_addresses),
            source=Source.THEMIS,
            tags=["themis", self.name],
        )

    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        url = request.target if request.target_kind == "url" else f"http://{host}"
        argv = [self.binary, "--url", url, "--format", "json", "--no-banner"]
        token = (
            get_env("THEMIS_WPSCAN_API_TOKEN") or get_env("AEGIS_WPSCAN_API_TOKEN") or ""
        ).strip()
        if token:
            argv += ["--api-token", token]
        return argv

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        text = output.stdout.strip()
        if not text:
            raise ParseError("wpscan produced no JSON output")
        check_json_depth(text, scanner=self.name)
        try:
            report = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseError("wpscan output is not valid JSON") from exc
        if not isinstance(report, dict):
            raise ParseError("wpscan output is not a JSON object")

        asset_id = self.asset_id(host)
        findings: list[Finding] = []

        version = report.get("version")
        if isinstance(version, Mapping):
            self._emit_vulnerabilities(findings, version, "WordPress core", asset_id, request)

        theme = report.get("main_theme")
        if isinstance(theme, Mapping):
            label = f"theme {self._slug(theme, 'main_theme')}"
            self._emit_vulnerabilities(findings, theme, label, asset_id, request)

        plugins = report.get("plugins")
        if isinstance(plugins, Mapping):
            for slug, plugin in plugins.items():
                if isinstance(plugin, Mapping):
                    self._emit_vulnerabilities(
                        findings, plugin, f"plugin {self._text(slug)}", asset_id, request
                    )

        interesting = report.get("interesting_findings")
        if isinstance(interesting, list):
            for item in interesting:
                if isinstance(item, Mapping):
                    self._emit_interesting(findings, item, asset_id, request)

        return findings

    def _emit_vulnerabilities(
        self,
        findings: list[Finding],
        container: Mapping[str, object],
        component: str,
        asset_id: str,
        request: ScanRequest,
    ) -> None:
        vulnerabilities = container.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            return
        for vuln in vulnerabilities:
            if not isinstance(vuln, Mapping):
                continue
            title = self._text(vuln.get("title")) or "undisclosed WordPress vulnerability"
            fixed_in = self._text(vuln.get("fixed_in"))
            references = vuln.get("references")
            cves = self._references(references, "cve", prefix="CVE-")
            urls = self._references(references, "url")
            evidence = [f"component={component}"]
            if fixed_in:
                evidence.append(f"fixed_in={fixed_in}")
            evidence.extend(cves)
            evidence.extend(urls[:5])
            description = f"WPScan reported a vulnerability in {component}."
            if fixed_in:
                description += f" Fixed in {fixed_in}."
            self.add_finding(
                findings,
                Finding(
                    asset_id=asset_id,
                    source=Source.THEMIS,
                    title=f"{component}: {title}",
                    description=description,
                    severity=Severity.MEDIUM,
                    evidence=evidence,
                    tags=["themis", self.name, "wordpress"],
                ),
                request,
            )

    def _emit_interesting(
        self,
        findings: list[Finding],
        item: Mapping[str, object],
        asset_id: str,
        request: ScanRequest,
    ) -> None:
        summary = self._text(item.get("to_s")) or self._text(item.get("type"))
        if not summary:
            return
        kind = self._text(item.get("type")) or "interesting finding"
        self.add_finding(
            findings,
            Finding(
                asset_id=asset_id,
                source=Source.THEMIS,
                title=f"WordPress disclosure: {kind}",
                description=summary,
                severity=Severity.INFO,
                evidence=[summary[:500]],
                tags=["themis", self.name, "wordpress"],
            ),
            request,
        )

    @staticmethod
    def _text(value: object) -> str:
        """Render a scalar as a stripped string; empty for None/containers."""
        if value is None or isinstance(value, (dict, list)):
            return ""
        return str(value).strip()

    @staticmethod
    def _slug(container: Mapping[str, object], fallback: str) -> str:
        slug = container.get("slug")
        return str(slug).strip() if isinstance(slug, str) and slug.strip() else fallback

    @staticmethod
    def _references(references: object, key: str, *, prefix: str = "") -> list[str]:
        """Return the reference identifiers under ``key`` (e.g. CVE ids), prefixed."""
        if not isinstance(references, Mapping):
            return []
        values = references.get(key)
        if not isinstance(values, list):
            return []
        out: list[str] = []
        for value in values:
            if value is None or isinstance(value, (dict, list)):
                continue
            text = str(value).strip()
            if not text:
                continue
            out.append(
                f"{prefix}{text}" if prefix and not text.upper().startswith(prefix) else text
            )
        return out
