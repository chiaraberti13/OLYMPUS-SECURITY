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

The implementation from PR
[#161](https://github.com/chiaraberti13/OLYMPUS-SECURITY/pull/161) remains active.
The latest verified `main` commit is
`0aef49b4a3c1fd262352cede3b15a1f708d0645c` (PR #187):

| Verification | Result |
| --- | --- |
| `ci` push run [43225425486](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/43225425486) | success |
| `codeql` push run [43225425551](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/43225425551) | success |
| `scanner-image` push run [43225425662](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/43225425662) | gate success |
| post-merge run [43226142363](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/43226142363) | 16/16 required checks on the exact SHA, success |
| retained artifact | `post-merge-0aef49b4a3c1fd262352cede3b15a1f708d0645c` (ID `13947497995`, 90 days) |

The SHA is recorded in `docs/verify/known-good.json`. Its `tag` and `release`
references are intentionally `null`: no signed release exists yet, and only
`CICD-3` may add those immutable references.

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

L'implementazione della PR
[#161](https://github.com/chiaraberti13/OLYMPUS-SECURITY/pull/161) è tuttora
operativa. L'ultimo commit verificato di `main` è
`0aef49b4a3c1fd262352cede3b15a1f708d0645c` (PR #187): i run `ci`
[43225425486](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/43225425486),
CodeQL [43225425551](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/43225425551)
e `scanner-image`
[43225425662](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/43225425662)
sono verdi sullo stesso SHA. Il verificatore post-merge
[43226142363](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/43226142363)
ha certificato 16/16 check e conservato per 90 giorni l'artefatto
`post-merge-0aef49b4a3c1fd262352cede3b15a1f708d0645c` (ID `13947497995`).

Lo SHA è registrato in `docs/verify/known-good.json`. `tag` e `release` restano
intenzionalmente `null`: non esiste ancora una release firmata e soltanto
`CICD-3` potrà aggiungere tali riferimenti immutabili.
