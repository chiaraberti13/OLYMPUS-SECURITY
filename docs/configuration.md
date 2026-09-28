# Configurazione Olympus

Olympus risolve ogni valore con questa precedenza, dalla più alta alla più bassa:

1. opzione passata esplicitamente dalla CLI o dal chiamante;
2. variabile `OLYMPUS_<SEZIONE>_<CHIAVE>`;
3. valore nel file TOML selezionato;
4. default integrato.

Per esempio, `[http].timeout` può essere sovrascritto da
`OLYMPUS_HTTP_TIMEOUT`. Un'opzione CLI specifica del comando prevale su entrambi.

Il file viene cercato in quest'ordine:

1. percorso indicato da `OLYMPUS_CONFIG`;
2. `./olympus.toml`;
3. `~/.olympus.toml`.

Se `OLYMPUS_CONFIG` indica un file assente o non valido, Olympus interrompe
l'operazione: non ripiega silenziosamente su un altro file o sui default.

## Validazione

```bash
olympus config validate
olympus config validate --file /percorso/olympus.toml
```

Il comando restituisce un documento JSON con sorgente, nomi degli override
environment attivi e configurazione effettiva. I valori associati a chiavi
sensibili (`token`, `password`, `secret`, `api_key` e simili) vengono sempre
sostituiti con `[REDACTED]`.

Gli override environment sono convertiti nel tipo del valore previsto e
validati con gli stessi limiti del TOML. Un valore non interpretabile o fuori
intervallo causa exit code `2`.

Le opzioni HTTP riconosciute sono `timeout`, `deadline`, `retries`, `backoff`,
`jitter`, `rate`, `max_response_bytes`, `max_response_headers`,
`max_response_header_bytes`, `max_redirects`, `max_decompressed_bytes` e
`max_expansion_ratio`.

La tabella `[observability]` è opzionale e usa gli stessi criteri di precedenza.
Le opzioni riconosciute sono `backend` (`none`, `prometheus`, `otlp`),
`cardinality_limit` (8–256), `service_name`, `otlp_endpoint` e
`prometheus_textfile`. Il default `none` non carica dipendenze, non invia dati e
non apre listener. Configurazione dei backend, metriche e confini di redazione
sono descritti in [Observability / Osservabilità](observability.md).

## Due file, due scopi

`olympus.toml` (questo documento) configura il **client HTTP** condiviso e
l'**osservabilità operativa** opzionale.
I **bound di esecuzione** — timeout, deadline, concorrenza, retry, backoff,
intervallo minimo, jitter — e il profilo `lab` vivono invece in un file
separato, `olympus.policy.toml`, con una propria catena di discovery
(`OLYMPUS_POLICY` → `./olympus.policy.toml` → `~/.olympus/policy.toml`) e i
propri comandi `olympus policy show|validate|diff|edit`.

La separazione è voluta: un file descrive *come si parla HTTP*, l'altro
descrive *quanto lavoro è autorizzato in questo engagement e verso quale
perimetro*. Vedi [policy di esecuzione editabile](policy.md).
