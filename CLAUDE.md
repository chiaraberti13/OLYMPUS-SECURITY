# CLAUDE.md — regole operative per Claude su questo repository

Queste istruzioni valgono per **ogni sessione** di Claude su OLYMPUS-SECURITY e
hanno priorità sulle abitudini predefinite dell'assistente.

## Merge in `main` — lo fa SEMPRE Claude (autorizzazione permanente dell'owner)

L'owner del repository **non riesce** a eseguire il merge dei PR: lo fa Claude.
Questa è un'autorizzazione esplicita e permanente a mergiare, non serve richiederla
di volta in volta.

Al termine di ogni task, dopo aver pushato il branch di sviluppo:

1. Individua (o, se manca, apri) la Pull Request del branch verso `main`.
2. **Attendi che tutti i check CI obbligatori siano verdi.** In particolare
   `ruff · format · mypy (required)`, i `pytest` su tutte le versioni Python,
   coverage e mutation. Un check `skipped` condizionale (es. `build · engine smoke
   test`) non è un fallimento.
3. **Mergia** la PR in `main` (metodo *merge commit*, coerente con lo storico),
   proteggendo il merge con l'`expectedHeadSha` (SHA completo a 40 caratteri).
4. Conferma all'owner che `main` è aggiornato.

**Se la CI non è verde, è compito di Claude risolvere i problemi** — in modo
autonomo e nella stessa sessione: leggi i log del job fallito, correggi la causa
reale nel codice/test/doc, ripusha, attendi la nuova esecuzione e **ripeti finché
tutti i check obbligatori sono verdi**, poi mergia. Non lasciare il merge in sospeso
segnalando solo il fallimento.

Vincoli invariati di sicurezza/integrità:

- **Mai** mergiare con un check obbligatorio rosso o in corso; **mai** bypassare,
  disabilitare o rendere non-bloccante un gate per far passare il merge. La CI
  rossa si risolve correggendo il difetto, non aggirando il controllo.
- Niente force-push distruttivi su `main`. Se il branch è già stato mergiato,
  ripartire dallo stesso nome da `main` aggiornato (fast-forward o force-with-lease
  solo su storia già mergiata).
- Non serve chiedere conferma per il merge: è pre-autorizzato qui. Resta valida la
  conferma per azioni distruttive esplicite (es. cancellare dati, riscrivere la
  storia di `main`).

## Prima di ogni push — verifica come la CI

Esegui i gate **con lo stesso scope della CI**, a livello di intero repo, per non
far fallire i check obbligatori:

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
