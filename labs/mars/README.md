# Mars — Cyber Range & Purple Lab

🇮🇹 Ambiente bersaglio isolato per **esercitarsi con i tool reali** di Olympus contro un
target *volutamente vulnerabile* — legale, locale, con soli dati sintetici. È così che ci si
allena davvero: strumenti funzionanti + un bersaglio autorizzato su cui usarli.

🇬🇧 An isolated target environment to **practise the real Olympus tools** against a
*deliberately vulnerable* target — legal, local, synthetic data only. That is how you actually
train: working tools + an authorized target to run them against.

> ⚠️ Solo dati sintetici, nessuna credenziale reale, in ascolto solo su `127.0.0.1`.
> Synthetic data only, no real credentials, listens on `127.0.0.1` only.

## Avvio / Start

```bash
# Diretto (consigliato) / directly (recommended)
python labs/mars/target/app.py        # http://127.0.0.1:8081

# Oppure via Docker / or via Docker
docker compose -f labs/mars/docker-compose.yml up
```

## Debolezze volute / Deliberate weaknesses
Il target espone, in modo controllato e non dannoso:
- `/app/search?q=…` — riflette il parametro **non-escapato** (XSS riflesso);
- `/app/admin`, `/app/.env`, `/app/backup.zip` — risorse "nascoste" sintetiche (discovery);
- `Server: nginx/1.18.0`, `X-Powered-By: PHP/8.1.0` — stack fingerprintabile;
- `/api/session/properties` — versione Metabase **affetta** da CVE-2026-72898 (solo fingerprint).

## Walkthrough — i tool contro il range / the tools against the range

```bash
S=labs/mars/target/practice-scope.json

# 1) Fingerprint dello stack / stack fingerprint
olympus artemis fingerprint --url http://127.0.0.1:8081/ --scope $S
#   -> nginx 1.18.0, PHP 8.1.0

# 2) Content discovery (dirbusting reale) / real dirbusting
olympus artemis content --url http://127.0.0.1:8081/app \
  --wordlist examples/input/artemis-content-wordlist.txt --scope $S --i-am-authorized
#   -> /admin, /.env, /backup.zip  (esposizioni sensibili -> LOW)

# 3) Reflected XSS
olympus artemis xss --url "http://127.0.0.1:8081/app/search?q=x" --param q \
  --scope $S --i-am-authorized
#   -> il parametro q riflette input non-escapato

# 4) Metabase CVE-2026-72898 (solo fingerprint, nessun payload SQLi)
olympus artemis metabase --url http://127.0.0.1:8081 --scope $S --i-am-authorized
#   -> versione v0.60.10 nel range affetto

# 5) Blue: rileva il post-exploitation su un endpoint dopo il foothold (purple end-to-end)
olympus apollo run --rules examples/input/apollo-redteam \
  --events labs/mars/target/mars-post-exploitation.ndjson
#   -> 7 alert: discovery, lateral movement, keylogging, webcam nascosta, C2 su DNS,
#      exfiltration, impact — le stesse tecniche di KLogger/symbiote, solo *rilevate*
```

Il passo 5 chiude il ciclo purple: il red side (1-4) ottiene un foothold sul target;
`mars-post-exploitation.ndjson` è una traccia di **eventi sintetici**, mai una cattura reale,
che riproduce cosa produrrebbe un endpoint compromesso in quella fase — e il blue side (Apollo)
la rileva. Nessun tastiera/webcam viene mai davvero acceduta: è così che si dimostra la tecnica
senza costruire lo spyware.

Ogni comando applica comunque lo **scope** (`practice-scope.json`): fuori perimetro viene
bloccato e loggato. Puoi generare un report unico con Vulcan a partire dai `--output` JSON dei
singoli tool. / Every command still enforces **scope**; out-of-scope targets are blocked and
logged. Feed each tool's `--output` JSON into Vulcan for one consolidated report.

Step 5 closes the purple loop: the red side (1-4) gets a foothold on the target;
`mars-post-exploitation.ndjson` is a **synthetic** event trace — never a real capture — that
reproduces what a compromised endpoint would emit at that stage, and the blue side (Apollo)
detects it. No keyboard or webcam is ever actually accessed: that is how the technique gets
demonstrated without building the spyware.
