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

    #: Why the last parsed run may be incomplete, or ``None`` for a clean,
    #: fully-completed scan. An adapter instance serves one run, so this is
    #: per-run state (reset on every :meth:`parse`); :meth:`coverage_loss`
    #: reports it as a partial result.
    _coverage_reason: str | None = None

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
        self._coverage_reason = None
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
        if root.tag != "nmaprun":
            # Well-formed XML that is not an nmap run (the wrong tool on PATH, or an
            # error document): it carries no ports, so silently it would read as a
            # clean target. Fail closed, exactly like an unparseable stream
            # (TOOLS-4.4).
            raise ParseError(f"nmap XML root is <{root.tag}>, not <nmaprun>")
        # nmap can exit 0 and still declare the scan failed in its run trailer
        # (<runstats><finished exit="error" errormsg="...">). A declared error is a
        # known error and must read as FAILED, never as a clean target.
        finished = root.find("runstats/finished")
        if finished is not None and finished.get("exit") == "error":
            errormsg = (finished.get("errormsg") or "").strip() or "no message"
            raise ParseError(f"nmap reported a failed scan: {errormsg}")
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
        # A trustworthy "no open ports" result is exit=success with the target
        # host actually up and scanned. Anything else means completeness is not
        # guaranteed, so the run is partial (exit 5) — never a silently clean
        # target (TOOLS-4.4).
        reasons: list[str] = []
        if finished is None or finished.get("exit") != "success":
            reasons.append("nmap did not report successful completion")
        hosts = root.findall("host")
        if not hosts:
            reasons.append("nmap returned no host record for the target")
        else:
            for host_el in hosts:
                status = host_el.find("status")
                state = status.get("state") if status is not None else None
                if state != "up":
                    reasons.append(
                        f"target host state is {state or 'unknown'}; its ports were not scanned"
                    )
                    break
        self._coverage_reason = "; ".join(reasons) if reasons else None
        return findings

    def coverage_loss(self, output: CommandOutput, request: ScanRequest) -> str | None:
        """Report why a parsed-but-incomplete nmap run reads as partial, not clean.

        nmap can exit 0 on a scan that did not finish or did not reach the target.
        A clean run is exit=success with the target host up; anything else means
        "no open ports" cannot be trusted, so the run is partial (TOOLS-4.4).
        """
        return self._coverage_reason
