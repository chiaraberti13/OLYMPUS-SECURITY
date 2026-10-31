"""Application use cases for authorized, DNS-pinned Artemis HTTP work."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from olympus.artemis.http import FetchResult, Resolver, Transport, fetch_scoped
from olympus.core.execution import Cancellation, ExecutionPolicy, NeverCancelled


@dataclass(frozen=True)
class ScopedFetchRequest:
    """Command-independent input and policy for one scoped GET flow."""

    url: str
    scope_path: Path
    audit_log_path: Path
    authorized: bool = False
    timeout_seconds: float = 5.0
    max_bytes: int = 1_000_000
    max_redirects: int = 5
    retries: int = 0


@dataclass(frozen=True)
class ScopedFetchService:
    """Authorize and execute one scope-safe, pinned, bounded HTTP flow."""

    resolver: Resolver
    transport: Transport
    cancellation: Cancellation = field(default_factory=NeverCancelled)

    def run(self, request: ScopedFetchRequest) -> FetchResult:
        policy = ExecutionPolicy(
            authorized=request.authorized,
            timeout_seconds=request.timeout_seconds,
            deadline_seconds=request.timeout_seconds * (request.max_redirects + 1),
            retries=request.retries,
        )
        return fetch_scoped(
            request.url,
            request.scope_path,
            request.audit_log_path,
            self.resolver,
            self.transport,
            max_bytes=request.max_bytes,
            max_redirects=request.max_redirects,
            policy=policy,
            cancellation=self.cancellation,
        )
