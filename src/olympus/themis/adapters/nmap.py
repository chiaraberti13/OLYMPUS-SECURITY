"""Real nmap adapter: parses nmap XML into open-port/service findings."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from olympus.core.enums import Severity, Source
from olympus.core.models import Finding
from olympus.themis.base import ParseError, ScannerAdapter
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput

_HIGH_RISK_PORTS = {23, 21, 3389, 5900, 445, 6379, 27017, 3306, 5432, 9200}


class NmapAdapter(ScannerAdapter):
    name = "nmap"
    binary = "nmap"
    version_expected = "7.x"
    install = "apt-get install nmap"

    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        # -Pn: no ping (works on filtered hosts). -sV: service/version. -F: top
        # 100 ports (bounded). -oX -: XML to stdout. --host-timeout caps runtime.
        return [
            self.binary,
            "-Pn",
            "-sV",
            "--version-light",
            "-F",
            "--host-timeout",
            f"{max(request.timeout_seconds - 5, 30)}s",
            "-oX",
            "-",
            host,
        ]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        try:
            root = ET.fromstring(output.stdout)  # noqa: S314 - nmap output is trusted local
        except ET.ParseError as exc:
            raise ParseError(f"nmap XML unparseable: {exc}") from exc
        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        for port in root.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = int(port.get("portid", "0"))
            proto = port.get("protocol", "tcp")
            service = port.find("service")
            svc_name = service.get("name", "unknown") if service is not None else "unknown"
            product = service.get("product", "") if service is not None else ""
            version = service.get("version", "") if service is not None else ""
            banner = " ".join(p for p in (product, version) if p).strip()
            severity = Severity.MEDIUM if portid in _HIGH_RISK_PORTS else Severity.INFO
            evidence = [f"port={portid}/{proto}", f"service={svc_name}"]
            if banner:
                evidence.append(f"banner={banner}")
            self.add_finding(
                findings,
                Finding(
                    asset_id=asset_id,
                    source=Source.THEMIS,
                    title=f"Open port {portid}/{proto} ({svc_name})"
                    + (f" — {banner}" if banner else ""),
                    description=(
                        f"nmap found TCP port {portid} open running '{svc_name}'"
                        + (f" ({banner})." if banner else ".")
                    ),
                    severity=severity,
                    evidence=evidence,
                    remediation="Confirm the service is intended to be exposed; restrict access.",
                ),
                request,
            )
        return findings
