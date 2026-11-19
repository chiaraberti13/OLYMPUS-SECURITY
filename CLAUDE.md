# CLAUDE.md — regole operative per Claude su questo repository

Queste istruzioni valgono per **ogni sessione** di Claude su OLYMPUS-SECURITY e
hanno priorità sulle abitudini predefinite dell'assistente.

## Merge in `main` — lo fa SEMPRE Claude (autorizzazione permanente dell'owner)

L'owner del repository **non riesce** a eseguire il merge dei PR: lo fa Claude.
Questa è un'autorizzazione esplicita e permanente a mergiare, non serve richiederla
di volta in volta.

> **Stato CI (2026-11-19).** L'owner ha rimosso la pipeline `ci.yml` (il file è
> intenzionalmente vuoto). I **check obbligatori rimasti** sono soltanto due, dai
> workflow ancora attivi: **`CodeQL · Python · security-extended`** (`codeql.yml`)
> e **`scanner-image gate`** (`docker-build.yml`). I vecchi gate di `ci.yml`
> (ruff/format/mypy, pytest multi-versione, coverage, mutation, sandbox, smoke,
> container, pip-audit, gitleaks) **non vengono più eseguiti dalla CI**: restano
> utili come verifica locale consigliata (sotto), non come gate di merge.

Al termine di ogni task, dopo aver pushato il branch di sviluppo:

1. Individua (o, se manca, apri) la Pull Request del branch verso `main`.
2. **Attendi che i check obbligatori rimasti siano verdi** (`CodeQL` e
   `scanner-image gate`). Un check `skipped` condizionale non è un fallimento.
3. **Mergia** la PR in `main` (metodo *merge commit*, coerente con lo storico),
   proteggendo il merge con l'`expectedHeadSha` (SHA completo a 40 caratteri).
4. Conferma all'owner che `main` è aggiornato.

**Se un check obbligatorio rimasto non è verde, è compito di Claude risolvere i
problemi** — in modo autonomo e nella stessa sessione: leggi i log del job
fallito, correggi la causa reale, ripusha, attendi la nuova esecuzione e ripeti
finché i check obbligatori sono verdi, poi mergia. Non lasciare il merge in
sospeso segnalando solo il fallimento.

Vincoli invariati di sicurezza/integrità:

- **Mai** mergiare con un check obbligatorio rosso o in corso; **mai** bypassare o
  rendere non-bloccante un check obbligatorio *rimasto* per far passare il merge.
  Un check rosso si risolve correggendo il difetto, non aggirando il controllo.
  (La scelta di quali check siano obbligatori spetta all'owner: è lui che ha
  rimosso `ci.yml`; questa regola vale sui check che restano.)
- Niente force-push distruttivi su `main`. Se il branch è già stato mergiato,
  ripartire dallo stesso nome da `main` aggiornato (fast-forward o force-with-lease
  solo su storia già mergiata).
- Non serve chiedere conferma per il merge: è pre-autorizzato qui. Resta valida la
  conferma per azioni distruttive esplicite (es. cancellare dati, riscrivere la
  storia di `main`).

## Prima di ogni push — verifica locale consigliata

La CI non esegue più questi gate, ma restano il modo più rapido per non pushare
codice rotto. Eseguili a livello di intero repo quando tocchi codice/contratti/doc:

```bash
ruff check .
ruff format --check .      # repo-wide: formatta anche i blocchi di codice nei Markdown
python -m mypy --strict src/olympus
python scripts/export_schema_catalog.py --check
python scripts/check_doc_links.py
python -m pytest tests/unit tests/contract -q
```

Nota appresa: `ruff format` tratta anche gli snippet Python dentro i file `.md`;
controllare solo i file toccati non basta — usare `ruff format --check .`.
