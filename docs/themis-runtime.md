# Native THEMIS runtime — SEC-A

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

Prima di avviare API/Web, creare la directory degli scope e configurare
`OLYMPUS_THEMIS_API_KEY` (almeno 32 caratteri casuali) oppure `--identities` con
un registro di identità. Il flag `--i-am-authorized` e il controllo di scope
restano necessari per ogni job. `THEMIS_ENABLE_LIVE_SCANS` resta `false` per
default: una scansione disabilitata o un binario assente produce `partial`,
senza finding inventati. La Web UI usa cookie `Secure`: usare HTTPS anche per
la sessione browser locale. I bind non-loopback richiedono certificato e chiave.

Il worker continuo stampa una riga JSON quando è pronto e una per ogni job
terminato. Una singola scansione fallita/parziale non interrompe il servizio.
Ogni processo esegue un job alla volta; processi distinti condividono i claim
atomici e i lease SQLite. `--poll-interval` è limitato a 0,05–30 secondi.
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
`no-new-privileges`, tmpfs e limiti memoria/PID sono espliciti. La migrazione
non ha rete. Egress allowlist, seccomp e AppArmor specifici restano in SEC-B;
il test container SEC-A prova il runtime, senza dichiarare isolamento scanner
completo. Il profilo opzionale ZAP mantiene la sua chiave API obbligatoria;
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

Il sorgente VAP resta un archivio per provenance e confronto. La matrice di
parità per tutte le sue route, l'import dei dati legacy e il ritiro fisico del
sorgente restano punti separati della roadmap; non sono capacità dichiarate
di questo runtime.

## English

The installed wheel owns `themis api`, `serve`/`web`, `migrate` and `workers`.
API and Web share the native authenticated, scoped and audited job store.
Workers execute typed requests through the canonical application service,
with live scans disabled by default and explicit partial coverage for missing
or disabled engines. `serve` and `web` are the same command implementation.
Use HTTPS for browser sessions (`Secure` cookies); non-loopback binds require
a certificate and private key. Set a random 32+ character API credential or
provide an identity register; scopes and per-job authorization stay mandatory.

The continuous worker emits NDJSON readiness/completion records, runs one job
at a time and continues after individual job failures. Separate processes
share atomic SQLite claims/leases. Bounded polling is interruptible;
SIGINT/SIGTERM cancel active execution and stop new claims, returning `7`.
`--once` processes at most one job and preserves canonical exit codes:
`0` empty/clean, `1` findings, `4` denied, `5` partial, `6` failed/timed out,
`7` cancelled.

Migrations are idempotent and transactional for supported **native job**
databases. Foreign/VAP files, unsupported/future versions and symlinks are
refused; legacy data conversion is a separate SEC-A parity task. Stop services
before backing up, use SQLite backup or copy DB/WAL after all connections close,
and restore the native backup with its matching Olympus version for rollback.
Keep the old VAP volume separate; the native stack uses `themis-data`.

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
Scanner egress/seccomp/AppArmor completion remains SEC-B.

Run `make check`, `python scripts/smoke_native_runtime.py` and, on a Docker host,
`make test-container`. CI exercises clean-wheel and isolated-container startup
with real API/HTTPS Web servers and a disabled scanner job. These tests require
no external target. VAP source remains an archive pending the complete route
parity review and legacy data-import/removal milestones.
