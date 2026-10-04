---
name: roadmap-next
description: Avanza la roadmap di OLYMPUS-SECURITY. Usala ogni volta che il compito è completare il prossimo punto non spuntato di ROADMAP.md, verificarlo, spuntarlo e fare commit e push su main.
---

# Prossimo punto della roadmap — OLYMPUS-SECURITY

Procedura per una sessione automatica che deve chiudere **un** punto di `ROADMAP.md`
e pubblicarlo su `main` senza intervento umano. Segui i passi in ordine.

## 1. Allinea il repository

```bash
git checkout main
git pull --rebase origin main
python -m pip install -e ".[dev]"
```

Lavora sempre partendo dall'ultimo `main`: altre esecuzioni pianificate possono aver
spuntato punti poco prima di te.

## 2. Scegli il punto giusto

Trova i candidati con:

```bash
grep -n -E '^\s*[-*] \[ \]' ROADMAP.md | head -20
```

Il punto da fare è il **primo vero task** non spuntato, in ordine di documento, con
queste eccezioni:

- Le righe della legenda in cima sono scritte tra backtick (`` `[ ]` ``) e non
  compaiono nel grep: non vanno considerate.
- **Salta** i punti `[⏸]`: sono differiti perché richiedono laboratorio,
  infrastruttura o credenziali esterne.
- Un punto `[~]` (parziale) che precede il primo `[ ]` ha la precedenza, se la parte
  mancante è lavorabile da qui.
- Ogni intervento ha un ID stabile (`SEC-*`, `DEV-*`, `UX-*`, `OPS-*`, es. `SEC-A`):
  individualo dall'intestazione della sezione, serve per commit e roadmap.
- **Salta** i punti che non si possono chiudere da una sessione cloud: richiedono
  account o servizi esterni da attivare (Vercel, impostazioni GitHub, branch
  protection), credenziali reali, hardware, laboratorio live o decisioni della
  proprietaria. Passa al successivo e segnalalo nel resoconto finale.
- Se un punto è troppo grande per una sola sessione, completa una parte coerente e
  verificata e marcalo come **parziale** con la convenzione del repository (vedi
  sotto), mai come completato.

Prima di scrivere codice rileggi il punto, la sua sezione e il criterio di
completamento: il lavoro è finito solo quando quel criterio è soddisfatto.

## 3. Implementa

- Codice Python in `src/olympus`, tipizzato per passare `mypy --strict`.
- Non modificare `vendor/` se il punto non lo richiede esplicitamente: è la
  superficie VAP legacy da ritirare, non da estendere.
- Nessuna scansione o operazione network-active reale durante i test: usa fixture,
  mock e i marker pytest esistenti (`unit`, `contract`, `integration`,
  `posix_only`, `root_only`).
- Nuove superfici d'attacco o flussi di dati vanno riflessi nella documentazione in
  `docs/` nello stesso commit; se cambi schemi in `schemas/`, rigenera con
  `make schemas` e verifica con `make schemas-check`.
- Aggiorna `CHANGELOG.md` per modifiche visibili all'utente.

## 4. Verifica

Esegui i controlli che la CI esegue su questo repository e correggi ogni errore prima
di proseguire:

```bash
ruff check .
ruff format --check .
mypy --strict src/olympus
pytest -m "unit and not posix_only"
pytest -m "contract and not posix_only"
pytest -m "integration and not posix_only"
pytest -m "posix_only and not root_only"
```

`make check` raggruppa lint, format-check e type. Se hai toccato gli schemi esegui
anche `make schemas-check`.

Se un controllo fallisce per cause preesistenti estranee al punto (verificabile
eseguendolo anche su `main` senza le tue modifiche), non nasconderlo: annotalo nel
resoconto.

## 5. Aggiorna ROADMAP.md

Come richiesto da `CONTRIBUTING.md`, nello **stesso commit**: spunta il punto
(`[x]` se il criterio di completamento è soddisfatto e verificabile, `[~]` se è
parziale, con una riga su cosa resta), e aggiorna la dashboard di avanzamento e gli
indicatori della roadmap se il punto li modifica. Nulla va marcato più maturo delle
prove che lo sostengono.

## 6. Commit e push

```bash
git add -A
git status            # controlla che non ci siano file temporanei, .env o segreti
git commit            # messaggio secondo la convenzione sotto
git pull --rebase origin main
git push origin main
```

Convenzione dei messaggi: Conventional Commits con scope e **ID della roadmap nel soggetto**, es.
`feat(finding): suppression workflow (WEB-C)` oppure `docs: fix broken internal links
(DEV-G)`. Nel corpo spiega il perché e indica la prova (test che lo copre).

Se il push viene rifiutato perché `main` è avanzato, ripeti `git pull --rebase`,
risolvi gli eventuali conflitti (in `ROADMAP.md` tieni le spunte di entrambi), riesegui
i test interessati e ripeti il push. **Mai** `--force`, mai riscrivere la storia di
`main`, mai `--no-verify`.

## 7. Resoconto

Chiudi con un riepilogo breve: punto scelto (con ID), file modificati, controlli
eseguiti con esito, hash del commit ed esito del push, punti saltati e perché.
