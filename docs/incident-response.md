# Incident Response Runbook — Key & Credential Compromise

<p align="center"><a href="#english">🇬🇧 English</a> · <a href="#italiano">🇮🇹 Italiano</a></p>

This runbook covers suspected or confirmed compromise of the three credential
classes Olympus uses: **Ed25519 signing keys** (engagement manifests, Minerva
evidence, release artifacts), **CI tokens / GitHub Actions secrets**, and
**AEGIS/Themis API keys**. It documents a measurable path — contain → revoke →
rotate → re-sign → verify → communicate — so a reported compromise is handled
reproducibly. It describes only mechanisms that exist today; it is not a
production-readiness claim. See [`SECURITY.md`](../SECURITY.md) for reporting and
response-time targets and [`provenance.md`](provenance.md) for signing details.

## English

### First steps (any credential)
1. **Record** the time, who noticed, and the suspected exposure window; keep a
   timeline. Treat the window as "everything since the last known-good state".
2. **Contain**: stop using the suspect credential and prevent new use before
   investigating. Do not destroy logs — they are evidence.
3. **Classify** severity per [`SECURITY.md`](../SECURITY.md) (signing-key or API
   compromise is Critical) and start the matching playbook below.
4. **Preserve evidence** with Minerva where applicable (hashed, timestamped) so
   the response itself is auditable.

### Playbook A — Ed25519 signing key compromise
Applies to any private key produced by `olympus core keygen` and used by
`olympus core sign` (manifests, evidence, releases).

1. **Contain**: stop signing with the key; treat every artifact signed within
   the exposure window as untrusted until re-verified.
2. **Rotate**: generate a fresh keypair —
   `olympus core keygen --private new.key --public new.pub` (private key is
   written `0600`). Never reuse the old key material.
3. **Revoke trust**: stop distributing the old public key and remove it from every
   verifier's pinned trust set (verifiers pin the trusted public key with
   `olympus core verify --pubkey`). A signature is only as trusted as the pinned key.
4. **Re-sign** the still-valid artifacts with the new private key
   (`olympus core sign --key new.key`) and redistribute the new public key over a
   channel independent of the compromise.
5. **Verify**: confirm each re-signed artifact validates against the new pinned
   public key, and that artifacts signed by the old key in the window are rejected.
6. **Communicate**: notify consumers that the old public key is withdrawn and that
   artifacts must be re-verified; coordinate disclosure per `SECURITY.md`.

### Playbook B — CI token / GitHub Actions secret compromise
1. **Contain**: in the repository **Settings → Secrets and variables → Actions**,
   delete or rotate the exposed secret; if a token may still be live, revoke it at
   the issuing provider (e.g. a PAT or registry token in that provider's console).
2. **Audit**: review recent workflow runs and the Actions audit log for use of the
   token outside expected jobs; note any artifacts, releases or deployments it
   could have produced.
3. **Rotate downstream**: rotate any credential the token could read or write
   (including signing keys via Playbook A if the token could reach them).
4. **Rebuild**: re-run release/build workflows from a known-good commit with the
   rotated secrets, and treat artifacts built during the window as suspect until
   rebuilt and re-signed.
5. **Communicate**: record the rotation and, if published artifacts were affected,
   follow `SECURITY.md` disclosure.

### Playbook C — AEGIS/Themis API key compromise
Applies to named identities in the Themis identity register and to the legacy
shared key (`OLYMPUS_THEMIS_API_KEY`).

1. **Revoke** a named identity immediately:
   `olympus themis identities revoke <name>`. Revocation is stronger than expiry —
   it drops any secret still within its rotation overlap. The register is re-read
   when the file changes, so revocation takes effect without a restart.
2. **Rotate** if the identity must keep working:
   `olympus themis identities rotate <name> --overlap-seconds 300 --expires-in-days 90` issues a new
   secret (printed once) and keeps the previous one valid only briefly; distribute
   the new secret over a secure channel.
3. **Legacy shared key**: replace `OLYMPUS_THEMIS_API_KEY` with a fresh value and
   restart the API/Web process; prefer migrating to named identities with scopes
   and an expiry (`--expires-in-days`).
4. **Audit**: review the redacted API audit log for calls authenticated by the
   compromised key and the scopes they used, plus the `themis.identity.*`
   administration record; confirm no live-scan scope was abused.
5. **Communicate**: record the revocation/rotation and affected scopes.

### Post-incident
- Determine root cause and the exact exposure window; keep the evidence bundle.
- If the incident reveals a design gap, update [`threat-model.md`](threat-model.md)
  and open roadmap items.
- Confirm no secret entered source control (the blocking Gitleaks gate is the
  standing guard) and that rotations removed the old credential everywhere.

## Italiano

### Primi passi (qualsiasi credenziale)
1. **Registra** ora, chi ha rilevato e la finestra di esposizione sospetta; tieni
   una timeline. Considera la finestra come «tutto dall'ultimo stato valido noto».
2. **Contieni**: smetti di usare la credenziale sospetta e impediscine un nuovo uso
   prima di indagare. Non distruggere i log: sono evidenza.
3. **Classifica** la severità secondo [`SECURITY.md`](../SECURITY.md) (compromissione
   di chiave di firma o API è Critica) e avvia il playbook corrispondente.
4. **Preserva le evidenze** con Minerva ove applicabile (con hash e timestamp), così
   la risposta stessa è auditabile.

### Playbook A — Compromissione chiave di firma Ed25519
Vale per ogni chiave privata prodotta da `olympus core keygen` e usata da
`olympus core sign` (manifest, evidenze, release).

1. **Contieni**: smetti di firmare con la chiave; tratta ogni artefatto firmato nella
   finestra di esposizione come non fidato finché non è riverificato.
2. **Ruota**: genera una nuova coppia —
   `olympus core keygen --private new.key --public new.pub` (la chiave privata
   è scritta `0600`). Non riutilizzare mai il vecchio materiale di chiave.
3. **Revoca la fiducia**: smetti di distribuire la vecchia chiave pubblica e rimuovila
   dal set fidato pinnato di ogni verificatore (il verificatore pinna la chiave
   pubblica fidata con `olympus core verify --pubkey`). Una firma vale solo quanto la
   chiave pinnata.
4. **Rifirma** gli artefatti ancora validi con la nuova chiave privata
   (`olympus core sign --key new.key`) e ridistribuisci la nuova chiave pubblica su un
   canale indipendente dalla compromissione.
5. **Verifica**: conferma che ogni artefatto rifirmato validi con la nuova chiave
   pubblica pinnata e che gli artefatti firmati dalla vecchia chiave nella finestra
   siano rifiutati.
6. **Comunica**: avvisa i consumatori che la vecchia chiave pubblica è ritirata e che
   gli artefatti vanno riverificati; coordina la divulgazione secondo `SECURITY.md`.

### Playbook B — Compromissione token CI / secret GitHub Actions
1. **Contieni**: in **Settings → Secrets and variables → Actions** del repository,
   elimina o ruota il secret esposto; se un token può essere ancora attivo, revocalo
   presso l'emittente (es. un PAT o token di registry nella sua console).
2. **Audit**: esamina le run recenti dei workflow e l'audit log di Actions per usi del
   token fuori dai job attesi; annota artefatti, release o deploy che potrebbe aver
   prodotto.
3. **Ruota a valle**: ruota ogni credenziale che il token poteva leggere o scrivere
   (incluse le chiavi di firma via Playbook A se raggiungibili dal token).
4. **Ricostruisci**: riesegui i workflow di release/build da un commit valido noto con
   i secret ruotati; tratta come sospetti gli artefatti costruiti nella finestra
   finché non sono ricostruiti e rifirmati.
5. **Comunica**: registra la rotazione e, se coinvolti artefatti pubblicati, segui la
   divulgazione in `SECURITY.md`.

### Playbook C — Compromissione API key AEGIS/Themis
Vale per le identità nominate nel register Themis e per la chiave condivisa legacy
(`OLYMPUS_THEMIS_API_KEY`).

1. **Revoca** subito un'identità nominata:
   `olympus themis identities revoke <name>`. La revoca è più forte della scadenza:
   annulla ogni secret ancora nell'overlap di rotazione. Il register viene riletto al
   cambiamento del file, quindi la revoca ha effetto senza riavvio.
2. **Ruota** se l'identità deve continuare a operare:
   `olympus themis identities rotate <name> --overlap-seconds 300 --expires-in-days 90` emette un nuovo
   secret (stampato una sola volta) e mantiene il precedente valido solo per poco;
   distribuisci il nuovo secret su canale sicuro.
3. **Chiave condivisa legacy**: sostituisci `OLYMPUS_THEMIS_API_KEY` con un nuovo
   valore e riavvia il processo API/Web; preferisci migrare a identità nominate con
   scope e scadenza (`--expires-in-days`).
4. **Audit**: esamina l'audit log API redatto per le chiamate autenticate dalla chiave
   compromessa, gli scope usati e il record amministrativo `themis.identity.*`;
   conferma che nessuno scope di live-scan sia stato abusato.
5. **Comunica**: registra revoca/rotazione e gli scope interessati.

### Post-incidente
- Determina la causa radice e la finestra di esposizione esatta; conserva il bundle
  di evidenze.
- Se l'incidente rivela una lacuna di design, aggiorna
  [`threat-model.md`](threat-model.md) e apri voci di roadmap.
- Conferma che nessun segreto sia entrato nel repository (il gate bloccante Gitleaks è
  la guardia permanente) e che le rotazioni abbiano rimosso ovunque la vecchia
  credenziale.
