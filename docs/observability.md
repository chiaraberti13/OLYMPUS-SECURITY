# Observability / Osservabilità

Olympus emits operational metrics without copying audit data into telemetry.
Targets, URLs, paths, identities, error text, finding content, credentials and
engagement names are never metric labels. Dynamic labels are normalized and
limited to 64 distinct values per dimension by default; excess values collapse
into `other`.

Olympus emette metriche operative senza copiare i dati di audit nella
telemetria. Target, URL, percorsi, identità, testi di errore, contenuti dei
finding, credenziali e nomi degli engagement non diventano mai label. Le label
dinamiche sono normalizzate e limitate, per default, a 64 valori distinti per
dimensione; i valori eccedenti confluiscono in `other`.

## Backends

Install the optional exporters / Installa gli exporter opzionali:

```bash
python -m pip install -e ".[observability]"
```

The default is `none`, so a normal installation has no telemetry dependency and
opens no listener. Configure `olympus.toml` or the equivalent
`OLYMPUS_OBSERVABILITY_*` variables:

```toml
[observability]
backend = "otlp" # none | prometheus | otlp
cardinality_limit = 64
service_name = "olympus-security"
otlp_endpoint = "http://127.0.0.1:4318"
```

`otlp` exports metrics to `<endpoint>/v1/metrics` and traces to
`<endpoint>/v1/traces` over OTLP/HTTP. Athena assessments and AEGIS worker jobs
are therefore observable even when they are short-lived processes.

`otlp` esporta metriche verso `<endpoint>/v1/metrics` e trace verso
`<endpoint>/v1/traces` tramite OTLP/HTTP. Gli assessment Athena e i job dei
worker AEGIS restano quindi osservabili anche quando il processo dura poco.

For `prometheus`, the native AEGIS API exposes an authenticated `/metrics`
endpoint. It uses the same API credential and requires `capabilities:read`; the
endpoint is never public. Short-lived CLI/worker processes can atomically write
a Prometheus textfile on clean shutdown:

```toml
[observability]
backend = "prometheus"
prometheus_textfile = "/var/lib/node_exporter/textfile_collector/olympus.prom"
```

Con `prometheus`, l'API AEGIS nativa espone `/metrics` con autenticazione e
permesso `capabilities:read`; l'endpoint non è pubblico. I processi CLI/worker
brevi possono invece scrivere atomicamente un file Prometheus alla chiusura.

## Metrics

| Metric | Labels (bounded) | Meaning / Significato |
| --- | --- | --- |
| `olympus_assessments_total` | `component`, `outcome` | Completed assessments / assessment completati |
| `olympus_assessment_duration_seconds` | `component`, `outcome` | Assessment duration / durata assessment |
| `olympus_jobs_total` | `component`, `adapter`, `outcome` | Completed or requeued jobs / job conclusi o rimessi in coda |
| `olympus_job_duration_seconds` | `component`, `adapter`, `outcome` | Job duration / durata job |
| `olympus_artifacts_total` | `component`, `kind`, `format`, `outcome` | Evidence and reports / evidenze e report |
| `olympus_api_requests_total` | `component`, `method`, `route`, `status_class` | API requests by route template / richieste API per route template |
| `olympus_api_request_duration_seconds` | same as above / come sopra | API latency / latenza API |

API routes are recorded as templates (`/api/v1/jobs/{job_id}`), never as the
raw request path. Status is reduced to a bounded class such as `2xx` or `4xx`.

Le route API sono registrate come template (`/api/v1/jobs/{job_id}`), mai come
percorso grezzo della richiesta. Lo status è ridotto a una classe limitata come
`2xx` o `4xx`.

## Correlation and data boundaries / Correlazione e confini dei dati

Metrics intentionally omit assessment, job, evidence and report IDs because
those values would create unbounded time series. OpenTelemetry spans carry only
validated, opaque Olympus IDs (`olympus.assessment.id`, `olympus.job.id`,
`olympus.evidence.id`, `olympus.report.id`) to connect the lifecycle. Invalid or
path-like values are dropped.

Le metriche omettono intenzionalmente gli ID di assessment, job, evidence e
report, che produrrebbero serie temporali senza limite. Le span OpenTelemetry
contengono soltanto ID opachi Olympus validati per collegare il ciclo di vita;
valori non validi o simili a percorsi vengono scartati.

Telemetry is not an audit log and does not replace the evidence ledger. Apply
normal access control, retention and TLS to the collector. `olympus config
validate` shows the effective backend and only the names—not the values—of
active environment overrides.

La telemetria non è un audit log e non sostituisce il ledger delle evidenze.
Applica al collector controllo accessi, retention e TLS. `olympus config
validate` mostra il backend effettivo e soltanto i nomi, non i valori, degli
override environment attivi.
