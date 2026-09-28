"""Bounded, redaction-first metrics and trace correlation.

Operational telemetry is deliberately narrower than audit data. Metrics never
carry targets, paths, identities, error text, engagement names, or opaque object
identifiers. Assessment/job/evidence/report identifiers are admitted only as
span attributes, where they correlate one execution without multiplying metric
time-series cardinality.

The default backend is a dependency-free no-op. ``prometheus`` exposes a local
scrape payload, while ``otlp`` exports OpenTelemetry metrics and traces. Both
backends are optional and fail closed with an actionable configuration error
when their extra dependencies are missing.
"""

from __future__ import annotations

import importlib
import re
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from olympus.core.config import get
from olympus.core.fileio import atomic_write_bytes

BackendName = Literal["none", "prometheus", "otlp"]

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_LABEL = re.compile(r"[^a-z0-9_.:-]+")
_COMPONENTS = frozenset({"aegis", "apollo", "athena", "core", "minerva", "vulcan"})
_ARTIFACT_KINDS = frozenset({"evidence", "report"})
_ARTIFACT_FORMATS = frozenset({"json", "markdown", "ndjson", "sarif", "html", "pdf"})
_OUTCOMES = frozenset(
    {
        "cancelled",
        "failed",
        "findings",
        "partial",
        "policy_denied",
        "queued",
        "running",
        "succeeded",
        "timed_out",
    }
)


class ObservabilityConfigurationError(RuntimeError):
    """Raised when an explicitly enabled telemetry backend cannot start."""


@dataclass(frozen=True)
class Correlation:
    """Opaque, Olympus-generated identifiers allowed on traces but not metrics."""

    assessment_id: str | None = None
    job_id: str | None = None
    evidence_id: str | None = None
    report_id: str | None = None

    def attributes(self) -> dict[str, str]:
        attributes: dict[str, str] = {}
        for name, value in (
            ("assessment.id", self.assessment_id),
            ("job.id", self.job_id),
            ("evidence.id", self.evidence_id),
            ("report.id", self.report_id),
        ):
            if value is not None and _SAFE_IDENTIFIER.fullmatch(value):
                attributes[f"olympus.{name}"] = value
        return attributes


@dataclass(frozen=True)
class MetricRecord:
    """One normalized record retained by the deterministic test exporter."""

    name: str
    kind: Literal["counter", "histogram"]
    value: float
    attributes: tuple[tuple[str, str], ...]


class _Exporter(Protocol):
    def counter(self, name: str, value: float, attributes: Mapping[str, str]) -> None: ...

    def histogram(self, name: str, value: float, attributes: Mapping[str, str]) -> None: ...

    @contextmanager
    def span(self, name: str, attributes: Mapping[str, str]) -> Iterator[None]: ...

    def prometheus_payload(self) -> tuple[bytes, str] | None: ...

    def shutdown(self) -> None: ...


class _NoopExporter:
    def counter(self, name: str, value: float, attributes: Mapping[str, str]) -> None:
        return None

    def histogram(self, name: str, value: float, attributes: Mapping[str, str]) -> None:
        return None

    @contextmanager
    def span(self, name: str, attributes: Mapping[str, str]) -> Iterator[None]:
        yield

    def prometheus_payload(self) -> tuple[bytes, str] | None:
        return None

    def shutdown(self) -> None:
        return None


class InMemoryExporter:
    """Thread-safe exporter used to prove labels and correlation in tests."""

    def __init__(self) -> None:
        self.records: list[MetricRecord] = []
        self.spans: list[tuple[str, tuple[tuple[str, str], ...]]] = []
        self._lock = threading.Lock()

    def _append(
        self,
        name: str,
        kind: Literal["counter", "histogram"],
        value: float,
        attributes: Mapping[str, str],
    ) -> None:
        record = MetricRecord(name, kind, value, tuple(sorted(attributes.items())))
        with self._lock:
            self.records.append(record)

    def counter(self, name: str, value: float, attributes: Mapping[str, str]) -> None:
        self._append(name, "counter", value, attributes)

    def histogram(self, name: str, value: float, attributes: Mapping[str, str]) -> None:
        self._append(name, "histogram", value, attributes)

    @contextmanager
    def span(self, name: str, attributes: Mapping[str, str]) -> Iterator[None]:
        with self._lock:
            self.spans.append((name, tuple(sorted(attributes.items()))))
        yield

    def prometheus_payload(self) -> tuple[bytes, str] | None:
        return None

    def shutdown(self) -> None:
        return None


class _PrometheusExporter:
    """Isolated Prometheus registry; no process-global collector collisions."""

    def __init__(self, textfile: Path | None = None) -> None:
        try:
            module = importlib.import_module("prometheus_client")
        except ModuleNotFoundError as exc:
            raise ObservabilityConfigurationError(
                "Prometheus metrics require `pip install olympus-security[observability]`"
            ) from exc
        self._module: Any = module
        self._registry: Any = module.CollectorRegistry(auto_describe=True)
        self._counters: dict[tuple[str, tuple[str, ...]], Any] = {}
        self._histograms: dict[tuple[str, tuple[str, ...]], Any] = {}
        self._lock = threading.Lock()
        self._textfile = textfile

    def _instrument(
        self,
        collection: dict[tuple[str, tuple[str, ...]], Any],
        factory_name: str,
        name: str,
        attributes: Mapping[str, str],
    ) -> Any:
        labels = tuple(sorted(attributes))
        key = (name, labels)
        with self._lock:
            instrument = collection.get(key)
            if instrument is None:
                factory = getattr(self._module, factory_name)
                instrument = factory(
                    name,
                    f"Olympus {name.replace('_', ' ')}.",
                    labelnames=labels,
                    registry=self._registry,
                )
                collection[key] = instrument
        return instrument.labels(**dict(attributes))

    def counter(self, name: str, value: float, attributes: Mapping[str, str]) -> None:
        self._instrument(self._counters, "Counter", name, attributes).inc(value)

    def histogram(self, name: str, value: float, attributes: Mapping[str, str]) -> None:
        self._instrument(self._histograms, "Histogram", name, attributes).observe(value)

    @contextmanager
    def span(self, name: str, attributes: Mapping[str, str]) -> Iterator[None]:
        yield

    def prometheus_payload(self) -> tuple[bytes, str] | None:
        payload = cast(bytes, self._module.generate_latest(self._registry))
        return payload, cast(str, self._module.CONTENT_TYPE_LATEST)

    def shutdown(self) -> None:
        if self._textfile is not None:
            payload = self.prometheus_payload()
            assert payload is not None  # noqa: S101 - this exporter always renders
            atomic_write_bytes(self._textfile, payload[0], mode=0o600)


class _OpenTelemetryExporter:
    """OTLP/HTTP exporter for both metrics and correlated execution spans."""

    def __init__(self, endpoint: str, service_name: str) -> None:
        try:
            metrics_sdk = importlib.import_module("opentelemetry.sdk.metrics")
            metrics_export = importlib.import_module("opentelemetry.sdk.metrics.export")
            metric_http = importlib.import_module(
                "opentelemetry.exporter.otlp.proto.http.metric_exporter"
            )
            trace_sdk = importlib.import_module("opentelemetry.sdk.trace")
            trace_export = importlib.import_module("opentelemetry.sdk.trace.export")
            trace_http = importlib.import_module(
                "opentelemetry.exporter.otlp.proto.http.trace_exporter"
            )
            resources = importlib.import_module("opentelemetry.sdk.resources")
        except ModuleNotFoundError as exc:
            raise ObservabilityConfigurationError(
                "OTLP export requires `pip install olympus-security[observability]`"
            ) from exc

        root = endpoint.rstrip("/")
        resource = resources.Resource.create({"service.name": service_name})
        metric_exporter = metric_http.OTLPMetricExporter(endpoint=f"{root}/v1/metrics")
        reader = metrics_export.PeriodicExportingMetricReader(metric_exporter)
        self._meter_provider: Any = metrics_sdk.MeterProvider(
            metric_readers=[reader], resource=resource
        )
        self._meter: Any = self._meter_provider.get_meter("olympus-security")

        trace_exporter = trace_http.OTLPSpanExporter(endpoint=f"{root}/v1/traces")
        self._tracer_provider: Any = trace_sdk.TracerProvider(resource=resource)
        self._tracer_provider.add_span_processor(trace_export.BatchSpanProcessor(trace_exporter))
        self._tracer: Any = self._tracer_provider.get_tracer("olympus-security")
        self._counters: dict[str, Any] = {}
        self._histograms: dict[str, Any] = {}
        self._lock = threading.Lock()

    def _instrument(self, collection: dict[str, Any], factory: str, name: str) -> Any:
        with self._lock:
            instrument = collection.get(name)
            if instrument is None:
                instrument = getattr(self._meter, factory)(
                    name, description=f"Olympus {name.replace('_', ' ')}."
                )
                collection[name] = instrument
        return instrument

    def counter(self, name: str, value: float, attributes: Mapping[str, str]) -> None:
        self._instrument(self._counters, "create_counter", name).add(
            value, attributes=dict(attributes)
        )

    def histogram(self, name: str, value: float, attributes: Mapping[str, str]) -> None:
        self._instrument(self._histograms, "create_histogram", name).record(
            value, attributes=dict(attributes)
        )

    @contextmanager
    def span(self, name: str, attributes: Mapping[str, str]) -> Iterator[None]:
        with self._tracer.start_as_current_span(name, attributes=dict(attributes)):
            yield

    def prometheus_payload(self) -> tuple[bytes, str] | None:
        return None

    def shutdown(self) -> None:
        self._meter_provider.shutdown()
        self._tracer_provider.shutdown()


class _CardinalityLimiter:
    """Keep dynamic labels bounded and collapse excess/unsafe values to ``other``."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._seen: dict[str, set[str]] = {}
        self._lock = threading.Lock()

    def normalize(self, dimension: str, value: str) -> str:
        normalized = _SAFE_LABEL.sub("_", value.strip().casefold())[:64].strip("_")
        if not normalized:
            return "other"
        with self._lock:
            seen = self._seen.setdefault(dimension, set())
            if normalized in seen:
                return normalized
            if len(seen) >= self._limit:
                return "other"
            seen.add(normalized)
        return normalized


class Observability:
    """Small semantic API shared by control-plane and assessment workflows."""

    def __init__(self, exporter: _Exporter | None = None, *, cardinality_limit: int = 64) -> None:
        if not 8 <= cardinality_limit <= 256:
            raise ValueError("cardinality_limit must be between 8 and 256")
        self._exporter = exporter or _NoopExporter()
        self._labels = _CardinalityLimiter(cardinality_limit)

    @staticmethod
    def _fixed(value: str, allowed: frozenset[str]) -> str:
        normalized = value.strip().casefold()
        return normalized if normalized in allowed else "other"

    def assessment_finished(self, component: str, outcome: str, duration_seconds: float) -> None:
        labels = {
            "component": self._fixed(component, _COMPONENTS),
            "outcome": self._fixed(outcome, _OUTCOMES),
        }
        self._exporter.counter("olympus_assessments_total", 1.0, labels)
        self._exporter.histogram(
            "olympus_assessment_duration_seconds", max(0.0, duration_seconds), labels
        )

    def job_finished(
        self, component: str, adapter: str, outcome: str, duration_seconds: float
    ) -> None:
        labels = {
            "component": self._fixed(component, _COMPONENTS),
            "adapter": self._labels.normalize("adapter", adapter),
            "outcome": self._fixed(outcome, _OUTCOMES),
        }
        self._exporter.counter("olympus_jobs_total", 1.0, labels)
        self._exporter.histogram("olympus_job_duration_seconds", max(0.0, duration_seconds), labels)

    def artifact_created(
        self, component: str, kind: str, artifact_format: str, outcome: str = "succeeded"
    ) -> None:
        labels = {
            "component": self._fixed(component, _COMPONENTS),
            "kind": self._fixed(kind, _ARTIFACT_KINDS),
            "format": self._fixed(artifact_format, _ARTIFACT_FORMATS),
            "outcome": self._fixed(outcome, _OUTCOMES),
        }
        self._exporter.counter("olympus_artifacts_total", 1.0, labels)

    def api_request(
        self, component: str, method: str, route: str, status_code: int, duration_seconds: float
    ) -> None:
        labels = {
            "component": self._fixed(component, _COMPONENTS),
            "method": self._labels.normalize("method", method),
            "route": self._labels.normalize("route", route),
            "status_class": f"{max(0, min(status_code // 100, 9))}xx",
        }
        self._exporter.counter("olympus_api_requests_total", 1.0, labels)
        self._exporter.histogram(
            "olympus_api_request_duration_seconds", max(0.0, duration_seconds), labels
        )

    @contextmanager
    def span(self, name: str, correlation: Correlation | None = None) -> Iterator[None]:
        safe_name = self._labels.normalize("span", name)
        attributes = correlation.attributes() if correlation is not None else {}
        with self._exporter.span(f"olympus.{safe_name}", attributes):
            yield

    def prometheus_payload(self) -> tuple[bytes, str] | None:
        return self._exporter.prometheus_payload()

    def shutdown(self) -> None:
        self._exporter.shutdown()


def observability_from_config(config: dict[str, Any] | None = None) -> Observability:
    """Build the explicitly selected backend from TOML/environment settings."""
    backend = str(get("observability", "backend", "none", config)).strip().casefold()
    limit = int(get("observability", "cardinality_limit", 64, config))
    if backend == "none":
        return Observability(cardinality_limit=limit)
    if backend == "prometheus":
        configured_textfile = str(get("observability", "prometheus_textfile", "", config)).strip()
        textfile = Path(configured_textfile).expanduser() if configured_textfile else None
        return Observability(_PrometheusExporter(textfile), cardinality_limit=limit)
    if backend == "otlp":
        endpoint = str(
            get("observability", "otlp_endpoint", "http://127.0.0.1:4318", config)
        ).strip()
        service_name = str(get("observability", "service_name", "olympus-security", config)).strip()
        if not endpoint.startswith(("http://", "https://")):
            raise ObservabilityConfigurationError(
                "[observability].otlp_endpoint must use http:// or https://"
            )
        if not _SAFE_IDENTIFIER.fullmatch(service_name):
            raise ObservabilityConfigurationError(
                "[observability].service_name must be an inert 1-128 character identifier"
            )
        return Observability(
            _OpenTelemetryExporter(endpoint, service_name), cardinality_limit=limit
        )
    raise ObservabilityConfigurationError(
        "[observability].backend must be one of: none, prometheus, otlp"
    )
