# SEC-4.3 — Post-merge and rollback evidence

## Baseline

The `main` merge commit `5d7affe5f403dc5a4fe4eb7251b2e24040e7dc97`
had 15 successful required check runs. The `scanner-image gate` context was
absent because the workflow-level push path filter prevented it from being
scheduled for unrelated changes. It is therefore not entered in the
known-good registry under the 16-check policy.

## Revert drill

The drill was executed on branch `codex/sec-4-3-post-merge`, never on `main`:

| Evidence | Commit / tree |
| --- | --- |
| Starting `main` commit | `5d7affe5f403dc5a4fe4eb7251b2e24040e7dc97` |
| Harmless marker commit | `35b5a2a15b9c3643654e9ab2f3105d52a9a89ace` |
| Revert commit | `0054332653fdf9b1dc5be39b18082217a02d6b4f` |
| Tree before the drill | `419e0bd14f4c057849f645175cb8143721be5991` |
| Tree after the revert | `419e0bd14f4c057849f645175cb8143721be5991` |

`git diff --exit-code 5d7affe5 00543326` returned zero. This proves that the
revert restored the exact starting tree; the two commits remain in history as
an auditable record.

## Closure evidence

This section is completed only after the implementation PR is merged and the
post-merge verifier reports all 16 required checks green on that exact merge
SHA. Until then, `docs/verify/known-good.json` intentionally remains empty.

---

# SEC-4.3 — Evidenza post-merge e rollback

## Stato iniziale

Il merge commit di `main` `5d7affe5f403dc5a4fe4eb7251b2e24040e7dc97`
aveva 15 check obbligatori verdi. Il contesto `scanner-image gate` era assente
perché il filtro dei percorsi applicato all'intero workflow ne impediva
l'avvio sulle modifiche non correlate. Lo SHA non viene quindi inserito nel
registro dei commit noti-buoni secondo la politica a 16 check.

## Prova di ripristino

La prova è stata eseguita sul branch `codex/sec-4-3-post-merge`, mai su `main`.
Il commit innocuo `35b5a2a1` è stato annullato da `00543326`; il tree iniziale
e quello ripristinato coincidono (`419e0bd1`). Il comando `git diff
--exit-code 5d7affe5 00543326` è terminato con codice zero. La cronologia
conserva entrambi i commit e rende la prova verificabile.

## Evidenza di chiusura

Questa sezione viene completata solo dopo il merge della PR e il risultato
verde del verificatore post-merge su tutti i 16 check dello stesso SHA. Fino
ad allora il registro `docs/verify/known-good.json` resta intenzionalmente
vuoto.
