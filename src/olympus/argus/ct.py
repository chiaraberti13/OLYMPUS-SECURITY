"""Passive Certificate Transparency subdomain discovery."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class CertificateTransparencyError(RuntimeError):
    """Raised when a Certificate Transparency response cannot be retrieved or decoded."""


class CertificateTransparencyClient(Protocol):
    """Provider of passive subdomain names from public certificate logs."""

    def discover(self, domain: str) -> list[str]:
        """Return normalized subdomains observed below ``domain``."""
        ...


def parse_crtsh_response(domain: str, payload: str) -> list[str]:
    """Extract safe, normalized in-domain names from a crt.sh JSON response."""
    normalized_domain = domain.lower().rstrip(".")
    suffix = f".{normalized_domain}"
    try:
        entries = json.loads(payload)
    except json.JSONDecodeError as exc:
        message = "invalid JSON returned by Certificate Transparency"
        raise CertificateTransparencyError(message) from exc
    if not isinstance(entries, list):
        raise CertificateTransparencyError("Certificate Transparency response must be a JSON array")

    names: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        value = entry.get("name_value")
        if not isinstance(value, str):
            continue
        for candidate in value.splitlines():
            name = candidate.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if name.endswith(suffix) and _is_dns_name(name):
                names.add(name)
    return sorted(names)


def _is_dns_name(name: str) -> bool:
    """Return whether ``name`` is a conservative ASCII DNS hostname."""
    if len(name) > 253:
        return False
    labels = name.split(".")
    return all(
        label
        and len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(character.isalnum() or character == "-" for character in label)
        and label.isascii()
        for label in labels
    )


@dataclass(frozen=True)
class CrtShClient:
    """Minimal read-only client for the public crt.sh JSON endpoint."""

    timeout: float = 10.0

    def discover(self, domain: str) -> list[str]:
        """Query crt.sh without probing any target-owned infrastructure."""
        query = urlencode({"q": f"%.{domain}", "output": "json"})
        request = Request(
            f"https://crt.sh/?{query}",
            headers={"User-Agent": "Olympus-Security-Argus/0.1"},
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                payload = response.read().decode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise CertificateTransparencyError(
                "failed to retrieve Certificate Transparency data"
            ) from exc
        return parse_crtsh_response(domain, payload)
