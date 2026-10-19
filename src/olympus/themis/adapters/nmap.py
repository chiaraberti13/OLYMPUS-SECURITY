"""Real nmap adapter: parses nmap XML into open-port/service findings."""

from __future__ import annotations

from io import BytesIO

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from olympus.core.enums import Severity, Source
from olympus.core.models import Finding
from olympus.themis.base import ParseError, ScannerAdapter
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput

_HIGH_RISK_PORTS = {23, 21, 3389, 5900, 445, 6379, 27017, 3306, 5432, 9200}
MAX_NMAP_XML_BYTES = 4 * 1024 * 1024
MAX_NMAP_XML_DEPTH = 64
MAX_NMAP_XML_ELEMENTS = 100_000


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
        xml_bytes = output.stdout.encode("utf-8")
        if len(xml_bytes) > MAX_NMAP_XML_BYTES:
            raise ParseError(f"nmap XML exceeds the {MAX_NMAP_XML_BYTES}-byte limit")
        try:
            # Nmap emits a harmless <!DOCTYPE nmaprun> declaration by default;
            # allow the declaration while forbidding entity expansion and all
            # external references.
            parser = ET.iterparse(
                BytesIO(xml_bytes),
                events=("start", "end"),
                forbid_dtd=False,
                forbid_entities=True,
                forbid_external=True,
            )
            depth = 0
            element_count = 0
            root = None
            for event, element in parser:
                if event == "start":
                    depth += 1
                    element_count += 1
                    if root is None:
                        root = element
                    if depth > MAX_NMAP_XML_DEPTH:
                        raise ParseError(
                            f"nmap XML exceeds the {MAX_NMAP_XML_DEPTH}-level depth limit"
                        )
                    if element_count > MAX_NMAP_XML_ELEMENTS:
                        raise ParseError(
                            f"nmap XML exceeds the {MAX_NMAP_XML_ELEMENTS}-element limit"
                        )
                else:
                    depth -= 1
            if root is None:
                raise ParseError("nmap XML has no root element")
        except (ET.ParseError, DefusedXmlException, LookupError, UnicodeError) as exc:
            raise ParseError(f"nmap XML unparseable: {exc}") from exc
        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        for port in root.iter("port"):
            portid_value = port.get("portid")
            if portid_value is None or not portid_value.isascii() or not portid_value.isdecimal():
                raise ParseError("nmap XML contains a non-numeric port id")
            portid = int(portid_value)
            if not 1 <= portid <= 65_535:
                raise ParseError("nmap XML contains a port id outside 1-65535")
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
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
