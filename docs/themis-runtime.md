# Native Themis runtime — SEC-A

## Italiano

`olympus themis api`, `serve`/`web`, `migrate` e `workers` eseguono il
control plane nativo dalla wheel installata. API e Web riusano autenticazione,
scope registrati, audit redatto e lo stesso archivio job; i worker eseguono
soltanto la richiesta tipizzata attraverso il servizio applicativo Themis.

```bash
pip install "olympus-security[themis]"
olympus themis migrate --database .olympus/themis-jobs.sqlite3
olympus themis api --scope-directory .olympus/scopes
olympus themis serve --scope-directory .olympus/scopes \
  --ssl-certfile cert.pem --ssl-keyfile key.pem
olympus themis workers --database .olympus/themis-jobs.sqlite3
olympus themis workers --once --database .olympus/themis-jobs.sqlite3
```

Per i job API/Web protetti da manifest firmato, API, Web e worker devono
condividere l'archivio revoche e la chiave pubblica dell'approvatore:

```bash
olympus themis workers --database .olympus/themis-jobs.sqlite3 \
  --engagement-storage .olympus/engagements \
  --manifest-public-key approver-ed25519-public.pem
```

Avviare anche il Web con `--engagement-storage .olympus/engagements
--manifest-public-key approver-ed25519-public.pem`: il wizard richiede il JSON
firmato, lo verifica in anteprima e di nuovo al submit, quindi lega il digest al
job. Senza la chiave fissata resta la modalità compatibile a conferma booleana,
che non costituisce il profilo protetto SEC-C.

L'API conserva il documento firmato verificato, non solo il digest. Prima di
avviare lo scanner il worker ricarica quel documento e ricontrolla firma,
digest, revoca, finestra, target e tecnica. Un digest senza documento o un
worker privo del verificatore viene classificato `policy_denied`, senza traffico.

Prima di avviare API/Web, creare la directory degli scope e configurare
`OLYMPUS_THEMIS_API_KEY` (almeno 32 caratteri casuali) oppure `--identities` con
un registro di identità. La chiave condivisa concede per default solo
`capabilities:read`; altri permessi si configurano esplicitamente con
`--api-key-scopes` (preferire identità nominate con privilegi minimi). Il flag
`--i-am-authorized` e il controllo di scope
restano necessari per ogni job. `THEMIS_ENABLE_LIVE_SCANS` resta `false` per
default: una scansione disabilitata o un binario assente produce `partial`,
senza finding inventati. La Web UI usa cookie `Secure`: usare HTTPS anche per
la sessione browser locale. I bind non-loopback richiedono certificato e chiave.

Il worker continuo stampa una riga JSON quando è pronto e una per ogni job
terminato. Una singola scansione fallita/parziale non interrompe il servizio.
Ogni processo esegue un job alla volta; processi distinti condividono i claim
atomici e i lease SQLite. Prima di ogni claim la stessa transazione conta i job
`running`: `--max-concurrent-jobs` (default 1, intervallo 1–4096) impone così un
limite aggregato fra tutti i worker sul medesimo database. Le repliche devono
usare lo stesso valore; lease scaduti sono recuperati prima del conteggio e non
bloccano capacità. `--poll-interval` è limitato a 0,05–30 secondi.
API e Web limitano per default a 64 le richieste concorrenti complessive tra i
processi che condividono lo stesso `--database`; il limite si può regolare con
`--max-concurrent-requests` (1–4096). Un sidecar SQLite `<database>.requests`
usa acquisizioni atomiche e lease rinnovabili: recupera capacità dopo un crash,
rifiuta con `503` e `Retry-After: 1` invece di accodare e non contiene payload o
identità. Tutte le repliche devono condividere lo stesso file e lo stesso limite;
deployment multi-host senza volume condiviso richiedono ancora un limite trusted
a monte. Il sidecar deve essere incluso nel backup solo per diagnostica, non per
il ripristino: le lease scadute vengono eliminate automaticamente.
`SIGINT`/`SIGTERM` interrompono anche l'attesa a coda vuota, propagano la
cancellazione allo scanner attivo e impediscono nuovi claim. Il servizio
termina con codice `7`; `--once` restituisce il codice canonico del job
(`0` coda vuota/nessun finding, `1` finding, `4` policy negata, `5` parziale,
`6` fallito/timeout, `7` cancellato).

### Migrazione e rollback

`migrate` crea o aggiorna **il database nativo dei job**, con DDL e versione in
un'unica transazione. Le migrazioni native già supportate conservano job,
idempotenza e stati; eseguirlo nuovamente è sicuro. Un database VAP/estraneo,
una versione futura o non supportata e un symlink sono rifiutati. Non puntare
il comando a `vap.db`: la conversione dei dati legacy richiede la successiva
matrice completa di parità SEC-A.

Fermare API/Web/worker prima del backup. Usare il backup SQLite (che include
il contenuto WAL) o copiare DB/WAL dopo la chiusura di tutte le connessioni.
Per il rollback fermare i servizi, ripristinare il backup nativo insieme alla
versione Olympus corrispondente e riavviare. Conservare il volume VAP
precedente separatamente; il nuovo stack usa `themis-data`. Evitare
`docker compose down -v` se si desidera conservare evidenze e job.

Prima di progettare una conversione, creare uno snapshot read-only del database
VAP archiviato:

```bash
olympus themis legacy-snapshot --source vap.db \
  --backup migration/vap.backup.sqlite3 \
  --output migration/vap.snapshot.json
```

Il comando non modifica `vap.db`, non crea job nativi e non accetta symlink o
destinazioni già esistenti. Il backup SQLite consistente e il manifest sono
owner-only. Il contratto `olympus.legacy-vap-snapshot` 1.0.0 registra digest,
conteggi, chiavi di migrazione deterministiche e decisioni sugli stati. Le righe
`queued`/`running` sono `blocked_active`, mentre stati sconosciuti o ambigui
restano `unmapped`: nessuna scansione viene riattivata senza nuova autorizzazione.
Target e query secret sono esclusi dal manifest: resta soltanto il digest del
target, mentre il valore originale rimane nel backup. Consent, audit e analytics
sono conteggiati ma esclusi dal manifest
perché richiedono valutazioni separate di finalità, privacy e provenienza.

Prima di usare lo snapshot come input per una futura conversione, verificare
insieme tutti e tre gli artefatti:

```bash
olympus themis legacy-verify --source vap.db \
  --backup migration/vap.backup.sqlite3 \
  --manifest migration/vap.snapshot.json
```

La verifica è in sola lettura e fallisce se sorgente, backup o manifest sono
cambiati, se il contratto non è esattamente la versione supportata, se
`PRAGMA integrity_check` fallisce o se l'inventario ricostruito dal backup non
coincide. Un esito positivo non autorizza né importa scansioni.

Generare quindi il piano revisionabile, ancora non eseguibile:

```bash
olympus themis legacy-plan --source vap.db \
  --backup migration/vap.backup.sqlite3 \
  --manifest migration/vap.snapshot.json \
  --output migration/vap.conversion-plan.json
```

Il contratto `olympus.legacy-vap-conversion-plan` 1.0.0 collega il piano ai
digest del manifest e del backup e classifica ogni record come terminale da
revisionare oppure da trattenere perché attivo, eliminato, con stato ambiguo o
senza adapter nativo. Non contiene target in chiaro, non eredita autorizzazioni
legacy e dichiara esplicitamente zero job eseguibili creati. Il file è
create-only e owner-only; la futura importazione richiederà un comando separato,
un engagement manifest corrente e un'ulteriore revisione SEC-A.

Approvare quindi soltanto le chiavi revisionate usando un manifest di engagement
corrente e la chiave pubblica dell'approvatore:

```bash
olympus themis legacy-approve --source vap.db \
  --backup migration/vap.backup.sqlite3 \
  --manifest migration/vap.snapshot.json \
  --plan migration/vap.conversion-plan.json \
  --signed-manifest engagement.signed.json \
  --manifest-public-key approver.pub.pem \
  --migration-key <sha256> \
  --output migration/vap.import-approval.json
```

Il contratto `olympus.legacy-vap-import-approval` 1.0.0 verifica nuovamente
snapshot e piano, firma Ed25519, revoche opzionali, finestra temporale, tecnica,
scope e limite dei target. Accetta solo record `review_terminal` selezionati
esplicitamente. Il receipt contiene digest e chiavi di migrazione, mai target in
chiaro; non considera autorizzata retroattivamente l'esecuzione storica e crea
zero job.

Importare infine soltanto le righe approvate come record terminali nativi:

```bash
olympus themis legacy-import --source vap.db \
  --backup migration/vap.backup.sqlite3 \
  --manifest migration/vap.snapshot.json \
  --plan migration/vap.conversion-plan.json \
  --approval migration/vap.import-approval.json \
  --signed-manifest engagement.signed.json \
  --manifest-public-key approver.pub.pem \
  --database .olympus/themis-jobs.sqlite3 \
  --output migration/vap.import-receipt.json
```

`legacy-import` rivalida l'intera catena, la firma, le revoche e lo scope al
momento dell'import. Scrive in una singola transazione record idempotenti già
terminali e con `authorized=false`: nessun worker può reclamarli. Un legacy
`completed` diventa `partial`, mai `succeeded`, perché findings e configurazione
non affidabili restano nel backup e nel job sono conservati solo i digest;
`failed` e `canceled` restano distinti. I parametri query sensibili del target
sono redatti prima della persistenza. Il receipt create-only
`olympus.legacy-vap-import-receipt` 1.0.0 contiene solo provenienza minimizzata,
ribadisce che l'esecuzione storica non è autorizzata retroattivamente e dichiara
zero job eseguibili.

### Docker

L'immagine `docker/Dockerfile` installa la wheel, include template/statici e
non copia `vendor/`. Il Compose avvia migrazione, API HTTPS, Web HTTPS e worker
SQLite senza broker. L'overlay scanner cambia soltanto l'immagine del worker.

Preparare **prima** dello startup:

1. `.olympus/scopes/` con i documenti di scope autorizzati;
2. `.olympus/config/themis-api-identities.json` con identità a minimo privilegio,
   generate da `olympus themis identities init/add --file …`;
3. `.olympus/tls/cert.pem` e `.olympus/tls/key.pem`, con certificato valido per
   l'hostname usato dal browser e chiave privata protetta.

Queste directory sono bind mount in sola lettura. File e directory devono
essere leggibili/attraversabili dall'UID/GID **10001:10001** del container;
il registro e la chiave restano owner-only (`0600`). Il worker riceve scope e
volume dati, senza registro credenziali o chiave TLS. L'immagine prepara il
volume dati con il proprietario corretto; per un volume già esistente verificare
la proprietà prima del riuso.

```bash
docker compose up --build
# API: https://localhost:8443 ; Web: https://localhost:8600
docker compose -f docker-compose.yml -f docker-compose.scanners.yml up --build
docker compose down
```

La configurazione fallisce all'avvio se mancano credenziali, scope o TLS.
Servizi non-root, filesystem root read-only, capability rimosse,
`no-new-privileges`, tmpfs e limiti memoria/PID sono espliciti. Il worker carica
inoltre il profilo seccomp default-deny versionato in
`deploy/security/themis-scanner-seccomp.json`; la migrazione non ha rete. Egress
allowlist, SELinux e provisioning automatico AppArmor restano in SEC-B. Sugli
host AppArmor compatibili è disponibile il profilo versionato
`deploy/security/olympus-themis-scanner.apparmor`, applicabile con l'overlay
`docker-compose.apparmor.yml`. Resta aperto anche l'obbligo container per le
esecuzioni CLI dirette. Il test container prova runtime e rifiuto di una syscall,
senza dichiarare isolamento scanner completo. Il profilo opzionale ZAP mantiene
la sua chiave API obbligatoria;
Compose richiede `THEMIS_ZAP_API_KEY` durante l'interpolazione anche quando
quel profilo non viene avviato.

### Evidenza ripetibile

- `make check`: lint, format, Mypy strict, schemi, coverage e mutation gate.
- `python scripts/smoke_native_runtime.py`: migrazione idempotente, API reale
  su loopback, accesso anonimo rifiutato, job parziale dal worker e Web HTTPS
  con template/CSS della distribuzione. Nessuna scansione live.
- `make test-container`: build e stessa verifica nell'immagine non-root,
  read-only e senza rete esterna. Docker è obbligatorio per questa suite.
- CI: lo smoke della wheel gira in un ambiente pulito; il job
  `native-container` valida Compose ed esegue la suite container.

Il sorgente VAP è stato rimosso fisicamente. Revisione, digest e inventario
immutabile delle route restano in
[`docs/parity/themis-vap-runtime.json`](parity/themis-vap-runtime.json); le
decisioni per ogni route e confine dati sono in
[`docs/parity/themis-vap-retirement.json`](parity/themis-vap-retirement.json).
I test contrattuali impongono l'assenza del tree e la completezza degli
inventari. Lo storico terminale mantiene il percorso di import revisionato,
senza conservare o rendere eseguibile il runtime legacy.

## English

The installed wheel owns `themis api`, `serve`/`web`, `migrate` and `workers`.
API and Web share the native authenticated, scoped and audited job store.
Workers execute typed requests through the canonical application service,
with live scans disabled by default and explicit partial coverage for missing
or disabled engines. `serve` and `web` are the same command implementation.
Use HTTPS for browser sessions (`Secure` cookies); non-loopback binds require
a certificate and private key. Set a random 32+ character API credential or
provide an identity register. A shared key defaults to `capabilities:read`;
grant additional permissions explicitly with `--api-key-scopes` (prefer named,
least-privilege identities). Scopes and per-job authorization stay mandatory.
API and Web default to 64 aggregate concurrent requests across processes that
share the same `--database`; tune this with `--max-concurrent-requests`
(1–4096). A `<database>.requests` SQLite sidecar uses atomic acquisitions and
renewable leases, recovers capacity after crashes, and contains no request
payloads or identities. Excess requests receive `503` with `Retry-After: 1`
instead of entering an unbounded queue. Every replica must share that file and
the same limit; multi-host deployments without a shared volume still need a
trusted upstream limit. The sidecar is diagnostic backup material only, not
restore state: expired leases are purged automatically.

The continuous worker emits NDJSON readiness/completion records, runs one job
at a time and continues after individual job failures. Separate processes
share atomic SQLite claims/leases and one aggregate `running` cap, configured
consistently with `--max-concurrent-jobs` (default 1, range 1–4096). Expired
leases are recovered before capacity is counted. Bounded polling is interruptible;
SIGINT/SIGTERM cancel active execution and stop new claims, returning `7`.
`--once` processes at most one job and preserves canonical exit codes:
`0` empty/clean, `1` findings, `4` denied, `5` partial, `6` failed/timed out,
`7` cancelled.

For API/Web jobs protected by signed manifests, start workers with the same
`--engagement-storage` and pinned `--manifest-public-key` used by the API and
Web. The submitting service retains the verified signed document alongside the
revocation register. The Web wizard verifies it at preview and again at launch;
without a pinned Web key, its compatibility confirmation mode is not the SEC-C
protected profile.
Immediately before scanner execution, the worker reloads it and rechecks the
signature, digest, revocation status, time window, target and technique. A bound
digest without its document or without a configured verifier becomes
`policy_denied` and produces no scanner traffic. With `--audit`, the worker
records that decision as `themis.manifest-authorization` (`authorized` or
`refused`) with the job ID, manifest digest and scanner; successful execution
then carries the same job ID and digest in `themis.native-scan` and in the
persisted `olympus.themis-result` 1.2.0 evidence document. URL query secrets
remain redacted and the signed document is never copied into audit or results.

Migrations are idempotent and transactional for supported **native job**
databases. Foreign/VAP files, unsupported/future versions and symlinks are
refused; legacy data conversion is a separate SEC-A parity task. Stop services
before backing up, use SQLite backup or copy DB/WAL after all connections close,
and restore the native backup with its matching Olympus version for rollback.
Keep the old VAP volume separate; the native stack uses `themis-data`.

Before any reviewed conversion, run `olympus themis legacy-snapshot --source
vap.db --backup migration/vap.backup.sqlite3 --output
migration/vap.snapshot.json`. The command opens the source read-only, creates a
consistent create-only backup and publishes the versioned
`olympus.legacy-vap-snapshot` 1.0.0 inventory. It records source/backup digests,
counts, deterministic migration keys and explicit state decisions without
creating native jobs. Active rows are blocked, ambiguous states remain unmapped,
and targets/query secrets are excluded from the inventory; only the target
digest remains. Consent, audit and product-analytics contents stay only in the
backup pending separate privacy and provenance reviews. Existing outputs and
symlinks are refused.

Before a future converter consumes the snapshot, verify the three artifacts
together with `olympus themis legacy-verify --source vap.db --backup
migration/vap.backup.sqlite3 --manifest migration/vap.snapshot.json`. The
read-only check fails if any artifact changed, the contract is not exactly the
supported version, SQLite integrity fails, or the inventory reconstructed from
the backup differs. Success neither authorizes nor imports a scan.

Next create the non-executable review plan with `olympus themis legacy-plan
--source vap.db --backup migration/vap.backup.sqlite3 --manifest
migration/vap.snapshot.json --output migration/vap.conversion-plan.json`.
The `olympus.legacy-vap-conversion-plan` 1.0.0 contract binds the plan to the
manifest and backup digests, then classifies each row as a terminal record for
review or retained because it is active, deleted, ambiguous, or lacks a native
adapter. It contains no plaintext target, inherits no legacy authorization and
explicitly creates zero executable jobs. The create-only, owner-only plan is
not an import; a later SEC-A step still needs a current signed engagement
manifest and a separate reviewed conversion command.

Approve only explicitly reviewed keys with `olympus themis legacy-approve`,
passing the snapshot, plan, current signed engagement manifest, pinned approver
public key, one or more `--migration-key` values, and a create-only output path.
The `olympus.legacy-vap-import-approval` 1.0.0 receipt re-verifies the snapshot
and plan plus Ed25519 signature, optional revocations, time window, technique,
scope and target limit. It accepts only `review_terminal` entries and exposes
digests rather than plaintext targets. It creates zero jobs and explicitly does
not claim retroactive authorization for historical execution.

Finally run `olympus themis legacy-import` with the same snapshot, plan,
approval, signed manifest and pinned key, plus the native database and a
create-only receipt path. The command re-verifies the full chain, revocation and
current scope before atomically writing idempotent terminal records with
`authorized=false`; workers can never claim them. Legacy `completed` becomes
native `partial`, never `succeeded`, because untrusted finding/configuration
bodies stay in the immutable backup and only their digests are carried forward.
`failed` and `canceled` remain distinct. Sensitive URL query values are redacted
before native persistence. The `olympus.legacy-vap-import-receipt` 1.0.0 output
contains minimized provenance, asserts no retroactive execution authorization
and records zero executable jobs.

Before Docker startup, prepare registered scopes under `.olympus/scopes`, the
scoped identity register under `.olympus/config/themis-api-identities.json`,
and valid TLS files under `.olympus/tls/{cert,key}.pem`. Mounts are read-only and
must be accessible to UID/GID **10001:10001**; credentials/private keys remain
owner-only. The worker receives neither credential register nor TLS key.
The image initializes data-volume ownership; check ownership before reusing an
existing volume. Both HTTPS ports are published only on host loopback.
Missing credentials/scopes/TLS fail startup. The optional ZAP key remains
required during Compose interpolation, even without selecting the profile.

`docker/Dockerfile` installs the wheel without copying vendor sources; the
scanner overlay changes only the worker image. Non-root, read-only rootfs,
dropped capabilities, no-new-privileges and resource limits are explicit.
The worker also loads the versioned, default-deny seccomp profile from
`deploy/security/themis-scanner-seccomp.json`; the container test proves a
forbidden syscall returns `EPERM`. Compatible AppArmor hosts can load
`deploy/security/olympus-themis-scanner.apparmor` and apply the
`docker-compose.apparmor.yml` overlay. Scanner egress, SELinux, automatic
AppArmor provisioning and mandatory
containerization of direct host CLI runs remain SEC-B.

The physical VAP source has been removed. Its reviewed revision, digest and
immutable route inventory remain in
[`docs/parity/themis-vap-runtime.json`](parity/themis-vap-runtime.json), while
[`docs/parity/themis-vap-retirement.json`](parity/themis-vap-retirement.json)
records one decision for every legacy route and data boundary. Contract tests
require the source tree to stay absent and the inventories to remain complete.
Reviewed terminal history can be imported without executable work or claims of
retroactive authorization.

Run `make check`, `python scripts/smoke_native_runtime.py` and, on a Docker host,
`make test-container`. CI exercises clean-wheel and isolated-container startup
with real API/HTTPS Web servers and a disabled scanner job. These tests require
no external target. The VAP source is no longer present; route/data retirement
decisions and the reviewed historical import path remain as immutable migration
evidence.
