# HTTP API reference

Every versioned Olympus HTTP endpoint, generated from the live OpenAPI schema of
the Themis application (`olympus.themis.api:create_app`) — the single source of
truth, so this page cannot drift from the real API. Each operation names the
versioned request/response contract it accepts and returns. Authentication uses
an API key or bearer token; the per-endpoint scope is documented in
`docs/web.md`. Do not edit the generated block by hand; run
`python scripts/generate_api_reference.py` (or `--check` in CI) instead.

<!-- GENERATED:api-reference START -->
### `POST /api/v1/apollo/evaluate`

| Tags | Request contract | Response contract |
| --- | --- | --- |
| apollo | `ApolloEvaluationRequest` | `olympus.apollo-evaluation` `1.0.0` |

### `GET /api/v1/apollo/rules`

| Tags | Request contract | Response contract |
| --- | --- | --- |
| apollo | — | `olympus.apollo-rule-list` `1.0.0` |

### `POST /api/v1/argus/ct-subdomains`

Extract in-domain subdomains from a Certificate Transparency export, offline.

| Tags | Request contract | Response contract |
| --- | --- | --- |
| argus | `ArgusCtRequest` | `olympus.argus-ct-subdomains` `1.0.0` |

### `POST /api/v1/artemis/fingerprint`

Fingerprint a captured HTTP response against the curated signatures, offline.

| Tags | Request contract | Response contract |
| --- | --- | --- |
| artemis | `ArtemisFingerprintRequest` | `olympus.artemis-fingerprint` `1.0.0` |

### `POST /api/v1/athena/plan`

Build a validated, signable assessment plan from a named profile, offline.

| Tags | Request contract | Response contract |
| --- | --- | --- |
| athena | `AthenaPlanRequest` | `olympus.athena-plan` `1.0.0` |

### `GET /api/v1/athena/profiles`

List the named, target-free scan profiles Athena can build plans from.

| Tags | Request contract | Response contract |
| --- | --- | --- |
| athena | — | `olympus.athena-profile-list` `1.0.0` |

### `GET /api/v1/capabilities`

| Tags | Request contract | Response contract |
| --- | --- | --- |
| capabilities | — | — |

### `GET /api/v1/engagements`

| Tags | Request contract | Response contract |
| --- | --- | --- |
| engagements | — | `olympus.themis-engagement-list` `1.0.0` |

### `GET /api/v1/engagements/{engagement_id}`

| Tags | Request contract | Response contract |
| --- | --- | --- |
| engagements | — | `olympus.engagement` `1.0.0` |

### `POST /api/v1/helios/identify-service`

Identify a service passively from a captured banner and/or port, offline.

| Tags | Request contract | Response contract |
| --- | --- | --- |
| helios | `HeliosIdentifyRequest` | `olympus.helios-service-identification` `1.0.0` |

### `POST /api/v1/hermes/scan-text`

Scan submitted text for secrets offline, returning only masked findings.

| Tags | Request contract | Response contract |
| --- | --- | --- |
| hermes | `HermesScanRequest` | `olympus.hermes-secret-scan` `1.0.0` |

### `GET /api/v1/jobs`

| Tags | Request contract | Response contract |
| --- | --- | --- |
| jobs | — | `olympus.themis-job-list` `3.0.0` |

### `POST /api/v1/jobs`

| Tags | Request contract | Response contract |
| --- | --- | --- |
| jobs | `JobSubmission` | `olympus.themis-job` `3.0.0` |

### `GET /api/v1/jobs/{job_id}`

| Tags | Request contract | Response contract |
| --- | --- | --- |
| jobs | — | `olympus.themis-job` `3.0.0` |

### `POST /api/v1/jobs/{job_id}/cancel`

| Tags | Request contract | Response contract |
| --- | --- | --- |
| jobs | — | `olympus.themis-job` `3.0.0` |

### `POST /api/v1/metis/extract`

Extract IOCs from free text, a STIX bundle or a MISP event, offline.

| Tags | Request contract | Response contract |
| --- | --- | --- |
| metis | `MetisExtractionRequest` | `olympus.metis-extraction` `1.0.0` |

### `POST /api/v1/minerva/verify-ledger`

| Tags | Request contract | Response contract |
| --- | --- | --- |
| minerva | `MinervaLedgerVerificationRequest` | `olympus.minerva-ledger-verification` `1.0.0` |

### `POST /api/v1/proteus/validate-campaign`

Validate and normalize awareness-campaign metadata, offline.

| Tags | Request contract | Response contract |
| --- | --- | --- |
| proteus | `ProteusCampaignValidationRequest` | `olympus.proteus-campaign-validation` `1.0.0` |

### `POST /api/v1/vulcan/correlate`

Correlate findings — and optionally Metis IOCs against Apollo events — offline.

| Tags | Request contract | Response contract |
| --- | --- | --- |
| vulcan | `VulcanCorrelateRequest` | `olympus.correlations` `1.0.0` |

### `POST /api/v1/vulcan/explain`

Explain one finding with the shared ``EXPL-1`` contract, offline.

| Tags | Request contract | Response contract |
| --- | --- | --- |
| vulcan | `olympus.finding` `1.0.0` | `olympus.finding-explanation` `1.0.0` |

### `GET /health`

| Tags | Request contract | Response contract |
| --- | --- | --- |
| operations | — | — |

### `GET /ready`

| Tags | Request contract | Response contract |
| --- | --- | --- |
| operations | — | — |
<!-- GENERATED:api-reference END -->
