# Verification status — baseline 2026-10-29; follow-up 2026-10-31

Baseline audit: `b5cc491ac466fc5875a40266151e3aa55730c82e`. The tested merge
`bca1daa` includes remote `e177498` and the SEC-E-01 audit fix `e8dea67`.
[Machine-readable checks](verify/audit-2026-10-29-checks.json) record commands,
counts, source digests and limitations. [Ecosystem audit](ecosystem-audit.md) and
[ROADMAP](../ROADMAP.md) define coverage and follow-up work.

## Follow-up snapshot — 2026-10-31

Since the baseline below, commits on `main` added and verified the following
offline changes: Metis backup integrity/foreign-key checks and atomic snapshot/
restore publication (`WEB-J-01`, partial),
purple telemetry schema/rejection accounting (`OPS-PURPLE-01`), corrected CI
claims (`DEV-G-01`, partial), exact dashboard aggregates for 205 jobs
(`WEB-G-01`), and explicit unavailable-state warnings for findings/incident
dashboard stores (`WEB-B-01`, partial). With the declared `themis`, `dev`, and
`report` extras installed, the complete `tests/unit/test_themis_web.py` module
passed 100 tests on Python 3.12; Ruff, format, and strict Mypy also passed for
the WEB-B changes. Failure injection covers `OSError` and symlink-loop
`RuntimeError` during findings and incident path resolution without path
disclosure. GitHub Actions CI separately passed all 14 jobs on `5dae81a`,
including Web and wheel smoke coverage. A broader focused jobs+Web run had one
unrelated environment failure while creating the sandbox scratch directory
(`EINVAL`); the remaining tests passed.

The local browser review was attempted, but the connected browser could not reach
the workspace's loopback-only test server (`ERR_CONNECTION_REFUSED`); no public
listener was opened and browser review remains incomplete.

WEB-J-01 now also exposes offline `ThemisJobStore` backup/verify/restore for
the single jobs SQLite database. Seven focused tests pass for WAL snapshot and
CLI round-trip, corruption/future-schema rejection, create-only restore,
sidecar refusal, preservation of an existing snapshot on failure, and dangling
symlink rejection. Ruff, format, strict Mypy and doc-link checks pass. The
combined job/backup unit run reports 70 passed and one pre-existing sandbox
failure: `test_durable_job_lifecycle` cannot create the isolated scratch
directory (`EINVAL`) before its subprocess assertion. The request-lease
`.requests` sidecar and other platform stores remain excluded; the returned
SHA-256 is informational unless an operator records a trusted reference.

The next WEB-J-01 slice adds independent `engagements.db` backup, verification
and create-only restore, exposed as `olympus engagement backup`,
`verify-backup` and `restore-backup`. The SQLite online snapshot includes the
engagement, signed-manifest and revocation tables; verification checks the exact
schema/version, integrity, foreign keys, standalone-file requirement and
fingerprint. Synthetic tests cover committed WAL data, round-trip through the
CLI, future-schema refusal, existing-destination preservation and sidecars.
This does not coordinate with Themis jobs, Metis, findings, audit, identity,
scope or evidence stores, and the hash is not an authenticated manifest.
On the preceding checkout, the focused engagement + Themis backup suites passed
**49** tests. Repository-wide `make lint`, `make format-check` and `make type`
passed (217 first-party files). On the current checkout, `make test` completed
with **2,682 passed, 17 failed,
2 skipped, 1 deselected**; all 17 failures are existing Themis sandbox/process
tests that cannot `chown` their temporary directory to `nobody` in this host
(`EINVAL`). No test or sandbox gate was disabled. Container, live-lab, coverage
and mutation gates were not run for that slice.

The following WEB-J-01 increment adds per-store recovery for the append-only
finding-lifecycle SQLite database. `olympus vulcan findings transitions backup`,
`verify-backup` and `restore-backup` are available. The snapshot preserves
encrypted row bytes and committed WAL state; verification checks schema,
version, SQLite integrity/foreign keys, absence of sidecars and a SHA-256
fingerprint, but does not decrypt or validate each transition document. Restore
is create-only. The encryption key is external and must be preserved separately;
if the source store did not have encryption configured, its records are plaintext.
Focused transition-store and backup CLI tests passed **19 tests**. The cross-store
manifest, audit/identity/scope/evidence stores and recovery drill remain open.

The next WEB-J-01 slice adds offline per-store snapshot, verification and
create-only restore for Athena's `athena.db` through `olympus athena store`.
SQLite online backup captures committed WAL state and includes plans,
assessments, jobs, inline results and audit rows. Verification checks schema
version/columns, SQLite integrity and foreign keys, absence of sidecars, plan
identity, and bounded result length/digest/identity/contracts. The CLI refuses
to create an empty store as a backup source. Four new synthetic tests cover
store and CLI round trips, WAL persistence, future schema refusal and preserving
an existing restore destination; the focused backup plus existing adapter
modules passed **26 tests**. The restore artifact's binary fingerprint may
differ while data/counts remain equal. This remains an independent store
snapshot: no cross-store point-in-time consistency, authenticated manifest, key
backup or RPO/RTO drill is established. On this checkout, full pytest reports
**2,686 passed, 17 failed, 2 skipped, 1 deselected**; all failures reproduce
the known host limitation where Themis sandbox tests cannot `chown` a scratch
directory to `nobody` (`EINVAL`). `make test-coverage` reports 89% line coverage
but stops on the same failures; its separate branch gate passes at **80.43%**
(75% minimum). Ruff, format, strict Mypy (217 source files), schema catalog
(24 contracts), generated CLI reference, changed-doc links and audit-exception
registry pass. A Python 3.12 wheel builds and installs in a clean environment;
`uv pip check` passes. `pip-audit` reports no known vulnerabilities for the
development environment. Gitleaks and Docker are unavailable locally. The
configured mutation gate passes: **1,237/2,009 targeted mutants killed
(61.6%)**. Its selectors target existing security boundaries and do not measure
the new backup methods directly.

For commit `50361cbfa7470a13c3d075932c48bf9da7f1118f`, local TestClient and
quality checks passed as above. The GitHub connector returned no Actions runs
for that commit (its workflow-run wrapper is PR-only) and did not expose CodeQL;
the combined status only reported the Vercel deployment check as failed. Do not
infer CI or CodeQL status for `50361cb` from the preceding green run.

On commit `bf3e22d`, GitHub Actions `ci` run
[41225520765](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/41225520765)
and CodeQL run
[41225520745](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/41225520745)
were observed. On commit `50d7496`, CI run
[41226041648](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/41226041648)
exposed a Python 3.11 TUI shutdown regression. On commit `0911d0b`, CI run
[41226565373](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/41226565373)
and CodeQL run
[41226565375](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/41226565375)
passed: pytest Python 3.11–3.14, branch coverage, mutation, POSIX sandbox,
Windows/macOS smoke, Ruff/format/Mypy, wheel, container, Gitleaks, pip-audit and
CodeQL. The fix awaits process-tree cleanup in Textual's actual
`CommandScreen.on_unmount` hook. The `/incidents` parity inventory mismatch from
the earlier run is corrected. On commit `5dae81a1829d4ed0893c6730b3b713308ec5f0c3`, GitHub Actions CI run
[41227141336](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/41227141336)
completed with all 14 jobs successful: pytest Python 3.11–3.14, branch coverage,
mutation, POSIX sandbox, Windows/macOS smoke (including Windows process-tree
cancellation), native container, wheel/clean install/API/Web/worker smoke,
SBOM, Ruff/format/Mypy, pip-audit and Gitleaks. The run follows the generated
Metis CLI reference refresh that corrected the earlier stale-reference failure.
The connector did not expose a CodeQL run result for this commit. The combined
commit status reports a Vercel deployment failure, separate from the successful
GitHub Actions CI run. Branch-protection inspection was denied by GitHub
integration (403), so required-check enforcement remains unverified. See the
current [ecosystem audit](ecosystem-audit.md) and
[roadmap](../ROADMAP.md) for scope-specific status.

## What actually ran

Linux, Python 3.12.14. Fresh editable install with dev/api/report/observability;
separate clean wheel install with api/report. No scanner execution against a real
or third-party target. The native smoke used only loopback with live scans off.

| Check | Outcome | Meaning / limitation |
|---|---|---|
| Four new SEC-E-01 regressions before fix | 4 failed as expected (28 October) | Proved old implementation loses history / accepts replacement |
| Targeted Athena tests after merge | **51 passed** | Duplicate rejection, competing connections, reopen/recover/cancel, existing Athena flows |
| Ruff lint / format | **Passed** | Full checkout |
| Mypy strict | **Passed**, 214 source files | First-party source |
| Schema catalog / audit exceptions | **Passed**, 24 versioned contracts | No active exception |
| `make test-coverage` | **Failed: 2468 passed, 17 failed, 67 deselected** | Same 17 sandbox failures observed before the fix; host cannot chown scratch to the sandbox user (EINVAL) |
| Standalone branch gate | **81.02%, passed** (minimum 75%) | Numeric coverage only; does not override failing tests |
| `make test-mutation` | **Passed**, 1231/1991 targeted mutants killed (61.8%) | Configured security functions only, not all application paths |
| Wheel / clean install / entry point / pip check | **Passed**, version 0.2.0 | Linux/Python 3.12 only |
| Native runtime smoke from wheel | **Passed** | Migration/idempotency, unauthenticated API rejection, disabled worker remains partial, HTTPS login/CSS |
| `make audit` | **Passed with local-package skip** after pip update | pip-audit cannot audit local Olympus 0.2.0 against PyPI |
| CycloneDX SBOM generator | **Generated** | Schema/conformance and PEP 508 closure correctness not established (SEC-F-02) |
| Hash lock generation | **Timed out after 120 s** | No lock produced; no hash-locked install claimed |
| `make secrets-scan` | **Unavailable**, executable missing | No Gitleaks working-tree/history/canary pass claimed |
| Quick benchmark | **Completed** | [Synthetic measurements](verify/audit-2026-10-29-benchmark.json); budgets not enforced |
| Internal documentation links / diff whitespace | **Passed** | External links not checked |

Initial `pip-audit` found 12 advisory entries (6 unique identifiers) in the fresh
venv's bootstrap pip 25.0.1. Upgrading that environment to pip 26.2.2 resolved
those findings without project dependency waivers. This is an environment fix,
not a claim that all possible Olympus vulnerabilities are excluded.

The failed full-suite cases are listed individually in the checks JSON. They
fail while preparing the isolated scratch directory, before their intended
subprocess assertions. No tests were disabled, no sandbox policy was weakened,
and no passing full `make check` is claimed. The earlier baseline on 28 October
reported 2435 passed / the same 17 failed / 67 deselected. Added upstream tests
and the new regression cases explain the changed final passing count.

## Remaining verifications and release limits

- Container/kernel egress, scanner lab/version compatibility: SEC-B-01, D1/D2/D11.
- Hash-locked rebuild and release signing/attestations: SEC-F-01/02. The CI
  workflow (`ci.yml`: quality, tests, coverage, mutation, gitleaks, pip-audit,
  SBOM) and CodeQL workflow (`codeql.yml`) are present and configured. A green
  run for the current commit and required branch-protection checks are not
  verified here; do not infer them from workflow-file presence.
- Real-browser SSE and accessibility, keyboard/screen-reader and IT/EN parity:
  WEB-A-01, UX-E-01. TestClient/Textual pilot tests are not a manual accessibility review.
- Supported Python/OS matrix: only Linux 3.12 was executed here; D12 remains open.
- Full backup/restore, state/audit atomicity and performance under a declared
  production workload: WEB-J-01, DEV-E-01/02/03.

The authorized-lab opt-in is never silently enabled by an automated audit. Use
`tests/live_lab/README.md` and `labs/mars/README.md` only after verifying the
isolated environment and signed scope. Mock/fixture success never promotes an
adapter to lab-verified or release-ready. No adapter was promoted in this audit.

## CI and publication

The GitHub branch response read on 29 October reported `protected=false`, with
no required status checks at that time. No repository policy was changed. The
quality workflow was restored on 30 October; current branch protection and
workflow run outcomes remain unverified. Final push/ref and workflow status are
verified separately in the delivery message; an empty run list is not a passed
pipeline.

## WEB-J-01 — manifest di backup coordinato (2026-10-31)

`olympus core backup-manifest` (create/`--verify`) vincola gli snapshot per-store in
un manifest SHA-256 deterministico e create-only; cinque test sintetici in
`tests/unit/test_backup_manifest.py` coprono round-trip, determinismo, file
modificato/mancante/extra, percorsi e symlink non sicuri, manifest malformato e CLI.
Non è autenticato (usare `core sign`), non garantisce consistenza point-in-time e non
copre identity, audit, custody o evidenze; nessun RPO/RTO è dichiarato.

## WEB-J-01 — backup del registro identità Themis (2026-10-31)

`olympus themis identities backup|verify-backup|restore` copia il registro in modo
create-only e `0600`, validandone contratto, duplicati e scope; tre test sintetici in
`tests/unit/test_themis_identity.py` coprono round-trip, rifiuto di overwrite/symlink/
corruzione e manomissione via CLI. Ruff, format e Mypy strict verdi; la suite
`not container and not live_lab` mostra 7 fallimenti preesistenti (sandbox POSIX,
runner, PDF, TUI, provenance) riprodotti anche senza questa modifica. Fingerprint non
autenticato; nessun RPO/RTO dichiarato. pip-audit, Gitleaks, CodeQL, build wheel e
container non eseguiti in questa sessione.

## WEB-J-01 — backup del ledger di custodia Minerva (2026-10-31)

`olympus minerva ledger-backup|ledger-verify-backup|ledger-restore` copia il ledger
byte per byte, create-only e `0600`, sotto il lock di append, verificando la catena di
hash prima e dopo. La firma risulta verificata solo con la chiave corrispondente. Sette
test sintetici in `tests/unit/test_minerva_ledger_backup.py` (compreso un backup con
append concorrenti) e la suite custody esistente passano; Ruff, format e Mypy strict
verdi. Fingerprint non autenticato; evidenze/vault, audit, scope e chiavi restano fuori;
nessun RPO/RTO dichiarato.

## WEB-J-01 — restore drill offline con RTO misurato (2026-11-01)

`olympus core restore-drill --workdir <nuova-dir>` (`core/restore_drill.py`) crea uno
store engagement, un ledger di custodia, un registro identità e un log di audit
**sintetici**, li snapshotta con i verificatori
dei rispettivi store, li lega in un `backup-manifest.json`, li ripristina in una
directory pulita e confronta i conteggi. I tempi sono misurati con clock monotono;
l'output dichiara dataset, store coperti e non coperti. Misura locale indicativa
(1000 engagement + 200 voci di custodia, questo host, disco locale): ripristino e
verifica ≈ 0,02 s. Le scritture successive allo snapshot risultano assenti dal
restore: la finestra di perdita dati coincide con l'intervallo dall'ultimo
snapshot, nessun RPO è promesso. Il drill include anche il database job Themis
(`--jobs`, job in stati diversi; conteggio per stato confrontato dopo il restore) e ha
rivelato sidecar `-wal/-shm` orfani lasciati da `ThemisJobStore.backup`, corretti e
coperti da test (31 test mirati superati; 9 fallimenti preesistenti di sandbox/PDF/TUI
nella suite completa, identici su main pulito). Include anche il file di scope Themis (SHA-256 e conteggi
confrontati dopo il restore) e lo store Athena (`--assessments`: piani, assessment, job, risultati e audit con conteggi confrontati). Include anche il DB append-only delle transizioni finding (`--transitions`: conteggio e storia di un finding confrontati dopo il restore; scritture successive non recuperate). Non copre
vault, evidenze e chiavi (la chiave di cifratura delle transizioni non fa parte dello snapshot). Tre test in
`tests/unit/test_restore_drill.py`; non è una garanzia RPO/RTO di produzione.

## WEB-B-01 — verifica browser reale dello stato store (2026-11-01)

`tests/integration/test_web_store_states_browser.py` esegue l'app Web su
`127.0.0.1` (porta effimera, dati sintetici) e la guida con Chromium via Playwright:
store engagement corrotto e directory findings con JSON invalido mostrano
"unavailable" e non onboarding vuoto/widget; store sano vuoto non mostra l'avviso.
Due test passati con Chromium 1243 preinstallato (`OLYMPUS_CHROMIUM`,
`OLYMPUS_CHROMIUM_NO_SANDBOX=1`); senza Playwright/Chromium il test viene saltato.
Solo Chromium, nessun audit di accessibilità.

## WEB-J-01 — backup del log di audit strutturato (2026-11-01)

`olympus core audit-backup backup|verify|restore` (`core/audit_backup.py`) copia
byte-esatta il log JSON-Lines scritto da `append_structured_audit` (Themis API/Web/job)
in un percorso nuovo `0600`, create-only. Prima di copiare e dopo la copia ogni riga è
validata: JSON valido, forma del record, `metadata` già redatta (una chiave sensibile
in chiaro fa rifiutare lo snapshot), coda troncata (scrittura interrotta) e limiti di
dimensione. Rifiuta destinazione esistente e symlink. Lo SHA-256 è un fingerprint non
autenticato; il log non ha catena di hash, quindi la verifica non prova autore né
completezza storica. Nessun lock cooperativo con gli scrittori: una copia con coda
parziale viene rifiutata e va ripetuta. Test sintetici: `tests/unit/test_audit_backup.py`.
Restano fuori scope, vault, evidenze, chiavi e snapshot point-in-time coordinato.

## WEB-J-01 — backup dello scope Themis (2026-11-01)

`olympus themis scope backup|verify-backup|restore` (`themis/scope_backup.py`) copia
byte-esatta il file di scope in un percorso nuovo `0600`, create-only. Ogni operazione
valida il documento con lo stesso `load_scope` usato prima di una scansione (contratto
strict, dimensione limitata, perimetro non vuoto): un perimetro che lo scanner
rifiuterebbe non viene salvato né ripristinato. Rifiuta destinazione esistente e
symlink; rileva modifica durante la copia. SHA-256 non autenticato. Dieci test sintetici
in `tests/unit/test_themis_scope_backup.py`, tutti passati. Lo scope Argus/Proteus non è
coperto. Quattro test preesistenti (`test_themis_execution`, `test_themis_web` PDF,
`test_tui`, `test_vulcan_provenance`) falliscono anche su main pulito in questo ambiente.
