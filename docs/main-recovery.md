# Main verification and recovery

## Automatic post-merge gate

[`post-merge-verify.yml`](../.github/workflows/post-merge-verify.yml) starts
after the `ci` workflow completes for a push to `main`. It checks out the exact
40-character merge SHA, reads the effective `main` rules and all check runs,
then invokes `scripts/audit_required_checks.py`. The audit succeeds only when:

1. the workflow definitions and the active ruleset contain the same 16 checks;
2. strict branch freshness is enabled;
3. every required check was executed successfully by its configured GitHub App
   on that exact SHA.

Missing or pending checks are retried for up to 15 minutes. A completed failed
check ends the verification immediately. The workflow has only `contents: read`,
`actions: read` and `checks: read`; it cannot modify content or settings. Its
Markdown report, rules response and complete check-run response are retained as
the `post-merge-<sha>` artifact for 90 days. A red run is the alert and blocks
promotion of the SHA to known-good.

## Known-good registry

[`verify/known-good.json`](verify/known-good.json) is the machine-readable
registry. Add an entry only after the automatic audit is green and record its
run URL and committed evidence document. Never rewrite an existing entry.

The `tag` and `release` fields stay `null` for ordinary merges. When `CICD-3`
creates a signed release, add immutable references in a later PR. Never move or
reuse a published tag; withdraw a defective release and create a higher patch
version from the recovered SHA.

## Recovery procedure

1. Preserve the failed run URL, artifact and affected SHA. Select the last
   verified SHA from the registry; do not infer it from a tag.
2. Create a recovery branch from current `main`, not from the older known-good
   commit: `git switch -c recovery/<incident> origin/main`.
3. Inspect parents with `git show --no-patch --pretty=raw <bad-sha>`. Revert a
   normal commit with `git revert <bad-sha>`. Revert a merge only after proving
   that parent 1 is the previous `main` tip: `git revert -m 1 <merge-sha>`.
4. Run the relevant local suite, push the branch and open a PR containing the
   incident reason, failed run, reverted SHA and data-impact assessment. All 16
   merge checks remain mandatory; recovery is not a bypass.
5. After merge, wait for the automatic post-merge gate. Register the recovery
   SHA only after a green exact-SHA result.

Never recover by deleting history, moving a tag, resetting `main`, or force
pushing. For database/schema changes, first prove that the down migration is
lossless. If it is not, restore from a tested backup or use a forward fix while
keeping application/schema compatibility; a source revert alone does not
recover data.

The reproducible drill and tree hashes are recorded in
[`verify/2026-11-07-post-merge.md`](verify/2026-11-07-post-merge.md).

---

# Verifica e ripristino di main

## Gate automatico post-merge

[`post-merge-verify.yml`](../.github/workflows/post-merge-verify.yml) si avvia
dopo il completamento del workflow `ci` per ogni push su `main`. Esegue il
checkout dello SHA completo del merge, legge le regole effettive di `main` e
tutti i check-run, quindi avvia `scripts/audit_required_checks.py`. La verifica
è verde soltanto se le definizioni dei workflow e il ruleset contengono gli
stessi 16 check, la branch freshness rigorosa è attiva e ogni check è stato
eseguito con successo dallo specifico GitHub App sul medesimo SHA.

I check mancanti o in corso vengono attesi per un massimo di 15 minuti; un
fallimento definitivo interrompe subito la verifica. Il workflow dispone solo
dei permessi `contents: read`, `actions: read` e `checks: read`. Conserva per 90
giorni report, regole e check-run nell'artefatto `post-merge-<sha>`. Un run rosso costituisce
l'avviso e impedisce di promuovere lo SHA a noto-buono.

## Registro degli SHA noti-buoni

[`verify/known-good.json`](verify/known-good.json) è il registro leggibile da
macchina. Una voce si aggiunge soltanto dopo il risultato verde del gate,
indicando URL del run ed evidenza committata. Le voci esistenti non si
riscrivono. Per i merge ordinari `tag` e `release` restano `null`; quando
`CICD-3` produrrà una release firmata, i riferimenti immutabili saranno aggiunti
con una PR successiva. Un tag pubblicato non va mai spostato o riutilizzato.

## Procedura di ripristino

1. Conservare URL, artefatto e SHA del run fallito. Selezionare l'ultimo SHA
   verificato dal registro, senza dedurlo da un tag.
2. Creare `recovery/<incidente>` dalla versione corrente di `origin/main`, non
   dal vecchio SHA noto-buono.
3. Controllare i parent con `git show --no-patch --pretty=raw <sha-errato>`.
   Usare `git revert <sha-errato>` per un commit normale. Per un merge, usare
   `git revert -m 1 <sha-merge>` soltanto dopo aver provato che il primo parent
   è il precedente tip di `main`.
4. Eseguire i test pertinenti, pubblicare il branch e aprire una PR con motivo,
   run fallito, SHA annullato e valutazione dell'impatto sui dati. Anche il
   ripristino deve superare tutti i 16 check: non è prevista alcuna scorciatoia.
5. Dopo il merge, attendere il gate automatico e registrare il nuovo SHA solo
   quando la verifica sullo stesso commit è verde.

Non cancellare la cronologia, non spostare tag, non eseguire reset o force-push
su `main`. Per variazioni di database o schema, verificare prima che la
migrazione inversa non perda dati; altrimenti ripristinare un backup collaudato
o applicare una correzione in avanti mantenendo la compatibilità. Il solo
revert del sorgente non ripristina i dati.

La prova riproducibile e gli hash dei tree sono in
[`verify/2026-11-07-post-merge.md`](verify/2026-11-07-post-merge.md).
