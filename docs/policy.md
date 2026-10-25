# Policy di esecuzione editabile

Fino alla versione precedente i limiti operativi di Olympus erano costanti in
`olympus/core/execution.py`. Cambiare un timeout per un singolo engagement
significava toccare il codice. Da ora quei numeri sono **dati**: si scrive un
file `olympus.policy.toml` e si rilancia il comando.

Il modulo di riferimento è `olympus.core.policy`; la CLI è `olympus policy`.

## Il punto fermo: i tetti non si alzano

Le costanti di `olympus.core.execution` (`MAX_TIMEOUT_SECONDS`,
`MAX_DEADLINE_SECONDS`, `MAX_CONCURRENCY`, `MAX_RETRIES`,
`MAX_BACKOFF_SECONDS`, `MAX_MIN_INTERVAL_SECONDS`, `MAX_JITTER_RATIO`) smettono
di essere *i valori* e diventano **i tetti massimi**.

Una policy può **abbassare** un limite, mai alzarlo sopra il tetto compilato.
Un file che ci prova viene **rifiutato al caricamento**, non silenziosamente
riportato al massimo: un operatore non deve mai credere che sia in vigore un
limite che non lo è.

| Bound | Minimo | Tetto (`MAX_*`) | Default |
| --- | --- | --- | --- |
| `timeout_seconds` | 0.05 | 3600 | 10 |
| `deadline_seconds` | 0.05 | 86400 | 600 |
| `max_concurrency` | 1 | 64 | 1 |
| `retries` | 0 | 5 | 0 |
| `backoff_seconds` | 0 | 60 | 0.5 |
| `min_interval_seconds` | 0 | 60 | 0 |
| `jitter_ratio` | 0 | 1 | 0 |

I default nella tabella sono quelli di `ExecutionPolicy`: il modulo li legge
dalla dataclass stessa, quindi le due fonti non possono divergere.

## Precedenza

Dalla priorità più alta alla più bassa:

1. override esplicito del chiamante o della CLI
   (`resolve_execution_policy(timeout_seconds=...)`);
2. variabile d'ambiente `OLYMPUS_POLICY_<CHIAVE>`
   (per esempio `OLYMPUS_POLICY_MAX_CONCURRENCY`);
3. profilo selezionato nel file (`[bounds.<profilo>]`);
4. tabella `[bounds.default]` del file;
5. default integrati di `ExecutionPolicy`.

Un override passato a `None` significa "non fornito" e lascia decidere ai
livelli sottostanti: una CLI può quindi inoltrare tutti i suoi flag senza
condizionali.

## Selezione del file

1. percorso indicato da `OLYMPUS_POLICY`;
2. `./olympus.policy.toml`;
3. `~/.olympus/policy.toml`.

Se `OLYMPUS_POLICY` (o `--file`) indica un file assente o non valido, Olympus
si ferma: non ripiega su un altro file né sui default. I due fallback impliciti
possono invece mancare, e in quel caso valgono i default integrati — quindi
un'installazione che non scrive mai una policy si comporta esattamente come
prima.

## Profili: overlay, non sostituzione

Un profilo con nome si sovrappone a `[bounds.default]`, non lo rimpiazza. Si
scrivono solo i numeri che cambiano.

```toml
schema_version = "1.0.0"
engagement     = "demo-2026"

[bounds.default]
timeout_seconds  = 10
deadline_seconds = 600
max_concurrency  = 4
retries          = 1
backoff_seconds  = 0.5
jitter_ratio     = 0.2

[bounds.aggressive]        # eredita timeout_seconds = 10 e jitter_ratio = 0.2
max_concurrency = 16
retries         = 3

[scope.domains]
allowed  = ["example.com"]
excluded = ["vpn.example.com"]
```

Con questo file, `--profile aggressive` produce `max_concurrency = 16`,
`retries = 3` e `timeout_seconds = 10`.

## Profilo `lab`

`[lab]` è l'unica tabella che **allarga** ciò che Olympus può raggiungere:
dichiara range privati che l'operatore possiede e che la SSRF guard
rifiuterebbe. Per questo è deliberatamente rumorosa.

```toml
[lab]
enabled          = true
allowed_networks = ["10.10.0.0/16"]   # range che dichiari di possedere
activated_by     = "operator@example.com"
activated_at     = 2026-01-01T00:00:00Z
```

Regole di validazione, tutte bloccanti:

- `enabled = true` senza `allowed_networks`, `activated_by` o `activated_at` è
  un errore: l'attivazione dev'essere esplicita e attribuibile;
- un CIDR malformato è un errore, non un'entrata ignorata;
- ogni range dev'essere **interamente contenuto** in uno degli intervalli
  ammissibili elencati sotto. Un'allowlist che può nominare qualsiasi cosa non è
  un'allowlist.

Intervalli ammissibili (`LAB_ELIGIBLE_RANGES`):

| Intervallo | Riferimento |
| --- | --- |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC 1918 |
| `100.64.0.0/10` | RFC 6598, carrier-grade NAT |
| `198.18.0.0/15` | RFC 2544, benchmarking |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | RFC 5737, TEST-NET |
| `fc00::/7` | RFC 4193, unique local |
| `2001:db8::/32` | RFC 3849, documentazione |

**Perché non basta controllare `is_global`.** È il punto in cui è facile
sbagliare: `ipaddress.ip_network("169.254.169.254/32").is_global` vale `False`.
Quel `/32` è l'endpoint dei metadati d'istanza di AWS, GCP e Azure — il bersaglio
SSRF di maggior valore che esista. Un validatore basato solo su `is_global` lo
accetterebbe. Per questo loopback (`127.0.0.0/8`, `::1`) e link-local
(`169.254.0.0/16`, `fe80::/10`) sono **esclusi di proposito**: un laboratorio
vive su spazio privato instradato, e "raggiungi il servizio di metadati" o
"raggiungi un servizio su questo host" non è ciò che un operatore intende con
"il range che possiedo".

Un range che *attraversa* il confine viene rifiutato: `10.0.0.0/7` contiene sia
RFC 1918 sia spazio pubblico, quindi non è ammissibile. Un CIDR scritto a partire
da un indirizzo host viene invece normalizzato: `10.10.0.5/16` diventa
`10.10.0.0/16`.

### Cosa cambia davvero nella guard

`olympus.core.addresses` mantiene due predicati distinti, e la differenza è il
punto centrale del disegno:

- `is_globally_routable(address)` resta **puro**: dice se l'indirizzo è una
  destinazione pubblica. Nessuna configurazione lo allarga, mai.
- `is_authorized_destination(address)` è il predicato **consapevole della
  policy**: pubblico → autorizzato; privato → autorizzato solo se rientra in un
  range dichiarato nel lab.

I wrapper IPv6 vengono srotolati prima del confronto, quindi
`::ffff:10.10.0.5` è valutato come `10.10.0.5` e non scivola oltre l'allowlist.
`resolve_authorized_addresses` usa il predicato consapevole, per cui la
risoluzione DNS di un host di laboratorio funziona, mentre una risposta che
contiene `127.0.0.1` resta rifiutata: il lab autorizza **i range dichiarati**,
non lo spazio privato in generale.

Il resto dei guardrail non si tocca: scope-check di modulo, gate di
autorizzazione sulle operazioni sensibili e IP pinning restano attivi. Quello
che cambia è **cosa dichiari come autorizzato**, e la lista è interamente in
mano tua.

### Record di attivazione

Ogni volta che il lab è attivo, Olympus produce un record di attestazione con
chi lo ha abilitato, quando, i range dichiarati e il digest SHA-256 del
documento di policy.

Se è configurata la chiave `OLYMPUS_POLICY_LAB_KEY`, il record viene firmato in
HMAC-SHA256 e riporta `"signed": true`. Senza chiave il record viene comunque
emesso, con digest, ma `"signed": false`: un record non firmato non viene mai
presentato come firmato.

### Esecuzione diretta Themis nel lab

Il record non firmato resta utile per ispezionare la configurazione, ma non può
abilitare traffico. Il profilo lab live è un percorso separato e più stretto:

```bash
export THEMIS_ENABLE_LIVE_SCANS=true
export OLYMPUS_POLICY_LAB_KEY='<chiave locale da secret provider>'
olympus themis run nmap --target 10.10.1.7 --scope ./scopes/lab.json \
  --i-am-authorized --lab-policy ./lab.policy.toml
```

`--lab-policy` richiede un file esplicito: non usa la discovery implicita. Il
documento deve avere `engagement`, `[lab].enabled`, attribuzione completa e
almeno un CIDR ammissibile; la chiave HMAC di almeno 32 byte, risolta tramite il
`SecretProvider`, è obbligatoria. Il target risolto deve
appartenere contemporaneamente allo scope JSON di Themis e alla allowlist lab.
Il controllo viene ripetuto immediatamente prima dell'adapter e registra digest
della policy e firma dell'attivazione nell'audit, senza registrarne la chiave.

Il profilo lab e il manifest Ed25519 sono mutuamente esclusivi. L'eccezione lab
vale solo per `themis run`: job, worker, API e Web continuano a richiedere il
manifest firmato, quindi non esiste un flag globale “allow all”. `--simulate`
non acquisisce né inventa provenienza lab.

## Comandi

```bash
olympus policy show                      # documento efficace, redatto, in JSON
olympus policy show --profile aggressive # risolve un profilo specifico
olympus policy validate                  # bloccante: esce 2 su documento invalido
olympus policy diff                      # solo i bound cambiati, con l'origine
olympus policy edit                      # crea il file da template e lo apre
```

`show` e `validate` passano l'output attraverso la redazione condivisa
(`redact_mapping`), quindi non stampano segreti né query string sensibili.

`diff` risponde alla domanda "cosa mi sta facendo questo file?" senza costringere
a ripercorrere mentalmente la catena di precedenza: per ogni bound cambiato
riporta default, valore efficace, tetto e **origine** (`[bounds.default]`,
`[bounds.<profilo>]` o `environment:<VARIABILE>`).

`edit` crea il file da un template commentato se non esiste — **non sovrascrive
mai** un file esistente — e lo apre con `$VISUAL`/`$EDITOR` quando una delle due
è impostata. `--no-open` si ferma alla creazione, ed è la forma da usare negli
script.

## Cosa una policy non può fare

L'autorizzazione resta una decisione del chiamante:
`resolve_execution_policy(..., authorized=...)` è un parametro Python, non un
campo del file. Nessun documento TOML può trasformare un'esecuzione non
autorizzata in una autorizzata.

## Riferimenti

- Contratto e ordine dei controlli: [`docs/execution-policy.md`](execution-policy.md)
- Configurazione generale (`olympus.toml`): [`docs/configuration.md`](configuration.md)
- Documentazione TOML: <https://toml.io/en/v1.0.0>
- Pydantic v2 (validazione del documento): <https://docs.pydantic.dev/latest/>
- Typer (CLI): <https://typer.tiangolo.com/>
