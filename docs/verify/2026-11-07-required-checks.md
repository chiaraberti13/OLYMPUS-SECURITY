# Required checks audit — 2026-11-07

Questa evidenza chiude il confronto richiesto da `SEC-4.2` tra i contesti definiti
nei workflow, i check eseguiti sullo stesso SHA e i check resi obbligatori dal
ruleset GitHub.

## Metodo riproducibile

Il ruleset verificato è
[`main protection`](https://github.com/chiaraberti13/OLYMPUS-SECURITY/settings/rules/26647563),
attivo sul branch predefinito, senza bypass e con branch freshness rigorosa. I due
documenti JSON usati dall'audit provengono da:

- `GET /repos/chiaraberti13/OLYMPUS-SECURITY/rulesets/26647563`;
- `GET /repos/chiaraberti13/OLYMPUS-SECURITY/commits/{sha}/check-runs?per_page=100`.

Il confronto si ripete con:

```bash
python scripts/audit_required_checks.py \
  48a830c7a60a7d6d8512d1053cb47648ebc422be \
  ruleset.json check-runs.json
```

Lo script deriva i nomi effettivi dai job e dalle matrix di `ci.yml`, `codeql.yml`
e `docker-build.yml`; non accetta risposte paginate incomplete, check prodotti da
una GitHub App diversa, run appartenenti a un altro SHA, ruleset non rigorosi o
drift tra workflow e regole. `scanner-image gate` gira sempre sulle pull request:
il build pesante viene eseguito solo per i percorsi interessati, mentre il gate
conclude verde anche quando quel build è correttamente saltato.

## Tabella generata

PR head: `48a830c7a60a7d6d8512d1053cb47648ebc422be`

| Check | Workflow source | Defined | Executed on this SHA | Successful | Required |
| --- | --- | --- | --- | --- | --- |
| CLI smoke · Windows · Python 3.11 | `.github/workflows/ci.yml#portable-smoke` | yes | yes | yes | yes |
| CLI smoke · macOS · Python 3.11 | `.github/workflows/ci.yml#portable-smoke` | yes | yes | yes | yes |
| CodeQL · Python · security-extended | `.github/workflows/codeql.yml#analyze` | yes | yes | yes | yes |
| POSIX sandbox · Python 3.11 · Ubuntu | `.github/workflows/ci.yml#posix-sandbox` | yes | yes | yes | yes |
| first-party branch coverage · Python 3.11 · Ubuntu | `.github/workflows/ci.yml#coverage` | yes | yes | yes | yes |
| gitleaks (blocking working-tree + history scan) | `.github/workflows/ci.yml#secret-scan` | yes | yes | yes | yes |
| native THEMIS container · no vendor · no live traffic | `.github/workflows/ci.yml#native-container` | yes | yes | yes | yes |
| pip-audit (blocking · runtime closure) | `.github/workflows/ci.yml#dependency-audit` | yes | yes | yes | yes |
| pytest · Python 3.11 · Ubuntu | `.github/workflows/ci.yml#tests` | yes | yes | yes | yes |
| pytest · Python 3.12 · Ubuntu | `.github/workflows/ci.yml#tests` | yes | yes | yes | yes |
| pytest · Python 3.13 · Ubuntu | `.github/workflows/ci.yml#tests` | yes | yes | yes | yes |
| pytest · Python 3.14 · Ubuntu | `.github/workflows/ci.yml#tests` | yes | yes | yes | yes |
| ruff · format · mypy (required) | `.github/workflows/ci.yml#quality` | yes | yes | yes | yes |
| scanner-image gate | `.github/workflows/docker-build.yml#gate` | yes | yes | yes | yes |
| security-boundary mutation tests · Python 3.11 · Ubuntu | `.github/workflows/ci.yml#mutation` | yes | yes | yes | yes |
| wheel · clean-install · CLI smoke | `.github/workflows/ci.yml#package-smoke` | yes | yes | yes | yes |

Strict branch freshness: `true`

Verdict: **PASS**

## Prova del blocco reale

La [PR #160](https://github.com/chiaraberti13/OLYMPUS-SECURITY/pull/160) è stata
aperta con head `c9bf2d59418342b2e8347a54df8f0ab2e23d5be6`. Il tentativo di merge immediato,
prima dell'esecuzione dei workflow, è stato respinto dall'API GitHub con HTTP 405
e il messaggio `16 of 16 required status checks are expected`. Il test dimostra
che un check solo definito, ma non ancora eseguito sullo SHA della PR, non può
soddisfare la regola. La policy `strict_required_status_checks_policy=true`
impedisce inoltre di unire un head non aggiornato rispetto a `main`.

## Interpretazione

La tabella dimostra i tre livelli separatamente: il check esiste nel workflow,
ha concluso con successo sullo SHA dichiarato ed è configurato come obbligatorio.
Il solo fatto che un workflow esista o sia verde su un altro commit non è
sufficiente. Le regressioni automatiche coprono anche l'assenza del gate
`scanner-image`, lo SHA errato, la branch freshness disabilitata, l'App sorgente
errata e la paginazione incompleta.
