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

PR [#161](https://github.com/chiaraberti13/OLYMPUS-SECURITY/pull/161) merged as
`5efe2c52469eca34311fba600a4550126a54dd39`. The independent push workflows
and the read-only post-merge verifier completed as follows:

| Verification | Result |
| --- | --- |
| `ci` push run [42372428237](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/42372428237) | success |
| `codeql` push run [42372428201](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/42372428201) | success |
| `scanner-image` push run [42372428186](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/42372428186) | build, engine smoke and gate success |
| post-merge run [42372721295](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/42372721295) | 16/16 required checks on the exact SHA, success |
| retained artifact | `post-merge-5efe2c52469eca34311fba600a4550126a54dd39` (ID `13573868787`, 90 days) |

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

La PR [#161](https://github.com/chiaraberti13/OLYMPUS-SECURITY/pull/161) è stata
unita come `5efe2c52469eca34311fba600a4550126a54dd39`. I run `ci`
[42372428237](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/42372428237),
`codeql` [42372428201](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/42372428201)
e `scanner-image`
[42372428186](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/42372428186)
sono verdi sullo stesso SHA. Il verificatore post-merge in sola lettura
[42372721295](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/42372721295)
ha certificato 16/16 check e conservato per 90 giorni l'artefatto
`post-merge-5efe2c52469eca34311fba600a4550126a54dd39` (ID `13573868787`).

Lo SHA è registrato in `docs/verify/known-good.json`. `tag` e `release` restano
intenzionalmente `null`: non esiste ancora una release firmata e soltanto
`CICD-3` potrà aggiungere tali riferimenti immutabili.
