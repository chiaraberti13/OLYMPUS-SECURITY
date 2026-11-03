# Aggiornare gli engine esterni

Roadmap: **TOOLS-4**. Questa è la procedura operativa per portare un engine (o una
sua dipendenza dati) a una nuova versione **in modo controllato e riproducibile**.
Il principio è uno solo: la versione che gira è **esattamente** quella dichiarata nel
manifest, e il manifest è l'**unica fonte di verità**.

> **Stato dell'automazione.** I comandi `olympus engines check-updates` e
> `olympus engines update <nome> --to <tag>` descritti come obiettivo in `TOOLS-4`
> **non esistono ancora** (Fase 4). Finché non ci sono, l'aggiornamento è la
> procedura **manuale** descritta qui sotto. `olympus engines list` e
> `olympus engines doctor` esistono e sono il modo supportato per *ispezionare* pin e
> presenza; non modificano nulla.

## 1. Che cosa è pinnato, e dove

Ogni engine ha un manifest `src/olympus/engines/<nome>/engine.toml`. Il pin vive in
`[engine]` (e nel `[engine.source]` corrispondente) e la sua forma dipende da
`distribution`:

| `distribution` | Campo di pin | Forma |
| --- | --- | --- |
| `go` | `pinned_version` | tag di modulo, es. `v3.11.1` (sempre con `v`) |
| `pip` | `pinned_version` + `source.package` | `nome==X.Y.Z` |
| `gem` | `pinned_version` + `source.package` | `nome -v X.Y.Z` |
| `git` | `source.commit` (+ `pinned_version` come tag leggibile) | **commit SHA-1 a 40 cifre** |
| `binary` | `source.sha256` (+ `source.url`) | checksum SHA-256 del file |
| `docker` | `source.digest` | `sha256:…` (mai un tag mobile) |
| `api` | — | nessun pin: prodotto esterno, mai eseguito |

Riferimenti mobili (`latest`, `main`, `master`, `head`, …) sono **vietati** dallo
schema (`olympus.engines.schema.MOBILE_REFERENCES`): un manifest che ne contiene uno
non valida. Il comando d'installazione mostrato all'operatore è **derivato** dal pin
(`EngineManifest.install_command()`, esposto agli adapter via
`olympus.engines.loader.install_hint`), quindi non può divergere dalla versione che
la build verifica — niente `@latest`, niente pacchetto sbagliato.

Le **dipendenze dati** (es. i template di nuclei) sono pinnate allo stesso modo in
`src/olympus/engines/_data/<nome>.toml` (per commit), perché cambiano ciò che
l'engine trova senza alcuna modifica al codice.

## 2. Policy di aggiornamento (`update_policy`)

Ogni manifest dichiara la cadenza con cui il pin va rivisto. Non è un automatismo: è
l'impegno che il team si prende sul *quando* guardare, e quanto salto è accettabile
senza una revisione dedicata dell'adapter.

| `update_policy` | Significato | Esempi |
| --- | --- | --- |
| `patch` | Solo correzioni (`X.Y.Z` → `X.Y.Z+1`). Aggiornabile con la sola suite verde. | — |
| `minor` | Fino a nuove feature compatibili (`X.Y` → `X.Y+1`). Rileggere le note di rilascio per cambi di output. | engine con parser stabile |
| `major` | Cambi potenzialmente rotti (`X` → `X+1`). Richiede revisione dell'adapter e nuovi test di contratto. | — |
| `manual` | Nessuna cadenza: il progetto upstream è lento, archiviato o il salto va sempre valutato a mano. | nmap, nuclei-templates |

Un cambio di **major**, o il passaggio di un engine `git` a un nuovo commit che
altera il formato di output, **non è mai** un semplice bump del pin: va accompagnato
dall'adeguamento del parser dell'adapter e dei test di contratto (vedi §4).

## 3. Procedura manuale di aggiornamento

Esempio: portare un engine `go` da `vA` a `vB`.

1. **Scegli la versione** rispettando `update_policy` e leggi le note di rilascio
   upstream (cosa cambia nell'output che l'adapter parsa).
2. **Modifica il manifest** `src/olympus/engines/<nome>/engine.toml`:
   - `go`/`pip`/`gem`: aggiorna `pinned_version` (e `source.package` se cambia).
   - `git`: aggiorna `source.commit` (SHA-1 completo) e il `pinned_version` leggibile.
   - `binary`: aggiorna `source.url` **e** `source.sha256`.
   - `docker`: aggiorna `source.digest`.
   Se l'engine è nell'immagine scanner, aggiorna il pin corrispondente in
   `docker/Dockerfile.scanners` (il formato è verificato, vedi §4).
3. **Rigenera l'inventario**:
   `python scripts/generate_engine_inventory.py --write` (riscrive
   `docs/engines/INVENTORY.md`; il gate CI usa `--check`).
4. **Adegua adapter e test** se il formato di output cambia: `build_argv`
   dall'allow-list del manifest, `parse`, `recognises`, le fixture di contratto.
   Aggiorna `evidence_version`/`reported_version` se differiscono dal tag, e metti
   `reviewed = true` **solo** quando `timeout_seconds`/`resource_profile` sono stati
   *misurati*, non stimati.
5. **Esegui i controlli locali** (§4) e correggi finché sono verdi.
6. **Commit** con un messaggio che cita il salto di versione e la `update_policy`
   applicata, così il diff di audit resta leggibile.

L'aggiornamento di una **dipendenza dati** è identico sul rispettivo
`_data/<nome>.toml` (nuovo `source.commit` e `pinned_version`).

## 4. Verifica (gate che tengono il pin onesto)

Nessun aggiornamento è "fatto" senza questi controlli verdi:

- `pytest -m "not container and not live_lab"` — in particolare:
  - `tests/unit/test_engine_manifests.py`: il manifest valida, il pin non è mobile,
    l'adapter dichiarato si importa.
  - `tests/unit/test_engine_install_hints.py`: l'hint d'installazione **uguaglia** il
    comando pinnato del manifest e non contiene riferimenti mobili o pacchetti errati.
  - `tests/unit/test_engine_dockerfile_pins.py`: `docker/Dockerfile.scanners`
    installa **esattamente** il pin del manifest (tag per go, `==`/`-v` per
    pip/gem, `git_pin … <commit> …` per git).
  - `tests/unit/test_engine_inventory_doc.py`: `docs/engines/INVENTORY.md` è
    rigenerato.
- `ruff check` · `ruff format --check` · `mypy --strict src/olympus`.
- `olympus engines doctor` sull'host (o nell'immagine): presenza, engine corretto
  (non un omonimo), versione/commit allineati al pin, dipendenze dati al commit
  giusto. Exit **8** (`ENGINE_MISSING`) se un `mandatory` non è a posto.
- **CI `scanner-image`** (`.github/workflows/docker-build.yml`): su ogni modifica
  sotto `src/olympus/engines/**` ricostruisce l'immagine e lancia
  `scripts/smoke_scanner_image.py`, che esegue il `presence_probe` di ogni engine
  *dentro l'immagine* e, per gli engine `git`, verifica `git rev-parse HEAD` contro
  il commit pinnato. È il precursore di `olympus engines doctor --strict`.

Se un controllo applicabile fallisce, si corregge e si ripete **prima** del push.

## 5. Rollback

Il pin è dati in git: per tornare indietro si **ripristina la versione precedente
del manifest** (e del `Dockerfile.scanners`/`_data` se toccati) e si rieseguono i
gate della §4. Poiché tutto deriva dal manifest, non restano stati nascosti da
ripulire; `olympus engines doctor` riconferma lo stato dopo il ripristino.

## 6. Automazione pianificata (TOOLS-4, Fase 4 — non ancora disponibile)

Questi strumenti renderanno la procedura sopra assistita e verificabile in CI; sono
**obiettivi**, non funzioni esistenti:

- `olympus engines check-updates`: risolve gli upstream, confronta i tag disponibili
  con il pin e riporta le differenze **senza aggiornare nulla**; segna
  `upstream_verified` come esito.
- `olympus engines update <nome> --to <tag>`: aggiorna il pin nel manifest, il
  lockfile/submodule corrispondente, riesegue i test dell'adapter e produce un diff
  di audit.
- osv-scanner sugli engine (oltre alla chiusura Python già coperta) e SBOM esteso
  alle dipendenze transitive degli engine, pubblicato come artefatto CI.

Fino ad allora, l'unica procedura supportata è quella **manuale** di questo
documento.
