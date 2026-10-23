# Examples — "Olympus Demo Corp"

🇮🇹 Dataset **sintetico** condiviso. `input/` dati d'ingresso, `output/` output dei moduli,
`reports/` report d'esempio. Nessun dato reale.

🇬🇧 Shared **synthetic** dataset. `input/` inputs, `output/` module outputs, `reports/`
sample reports. No real data.

## 🇮🇹 Esempi eseguibili (offline)

Questi comandi girano **senza rete e senza bersaglio** (nessun lab richiesto) e
sono **eseguiti in CI** da `tests/integration/test_examples_offline.py`, così la
documentazione non può invecchiare in silenzio. Gli output vanno in un file
temporaneo con `--output`.

```bash
# Blue team — valuta una regola di detection su un evento
olympus apollo test examples/input/apollo-rule.yaml examples/input/apollo-event.json \
  --output /tmp/alerts.json          # 1 alert, exit 0

# Carica e valida un pacchetto di regole
olympus apollo rules --rules examples/input/apollo-redteam   # exit 0

# DFIR — dal rilevamento all'incidente, poi verifica della catena di custodia
olympus minerva triage /tmp/alerts.json --title "Demo" --output /tmp/incident.json
olympus minerva verify examples/output/minerva-custody.json  # exit 0

# Secret scanning — trova la chiave sintetica di demo
olympus hermes scan examples/input/hermes-demo.txt --output /tmp/hermes.sarif  # exit 1 (finding)

# Esporta gli schemi JSON condivisi
olympus core export-schemas /tmp/schemas   # exit 0
```

> I comandi di rete (`olympus argus scan`, `olympus helios scan`, `olympus artemis …`)
> richiedono scope e autorizzazione esplicita e **non** sono offline: esercitarli
> solo contro il lab Mars incluso (`labs/mars/`) o un bersaglio autorizzato.

## 🇬🇧 Runnable examples (offline)

These commands run **with no network and no target** (no lab required) and are
**executed in CI** by `tests/integration/test_examples_offline.py`, so the docs
cannot rot silently. Write outputs to a temporary file with `--output`.

```bash
# Blue team — evaluate one detection rule against one event
olympus apollo test examples/input/apollo-rule.yaml examples/input/apollo-event.json \
  --output /tmp/alerts.json          # 1 alert, exit 0

# Load and validate a detection rule pack
olympus apollo rules --rules examples/input/apollo-redteam   # exit 0

# DFIR — detection to incident, then chain-of-custody verification
olympus minerva triage /tmp/alerts.json --title "Demo" --output /tmp/incident.json
olympus minerva verify examples/output/minerva-custody.json  # exit 0

# Secret scanning — find the synthetic demo key
olympus hermes scan examples/input/hermes-demo.txt --output /tmp/hermes.sarif  # exit 1 (finding)

# Export the shared JSON Schemas
olympus core export-schemas /tmp/schemas   # exit 0
```

> Network commands (`olympus argus scan`, `olympus helios scan`, `olympus artemis …`)
> require scope and explicit authorization and are **not** offline: exercise them
> only against the bundled Mars lab (`labs/mars/`) or an authorized target.
