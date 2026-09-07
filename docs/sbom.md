# SBOM — distinta dei materiali software

Olympus genera un **SBOM CycloneDX 1.5** della propria chiusura di dipendenze
runtime, con un comando nativo che non richiede tool esterni:

```bash
olympus core sbom                       # su stdout, con timestamp e serial
olympus core sbom -o sbom.json          # su file
olympus core sbom --reproducible        # senza timestamp/serial: byte-stable
olympus core sbom --extra aegis         # include l'extra opzionale 'aegis'
```

## Perché nativo e non solo Syft

La roadmap (§1.3, §3.5) chiede un SBOM in CI, e la risposta consueta è eseguire
**Syft** sull'immagine. Syft resta utile per il *container*, ma:

- lega l'SBOM alla presenza di un binario di terze parti;
- descrive l'**immagine**, non ciò che Olympus effettivamente importa.

`olympus.core.sbom` genera invece l'SBOM da `importlib.metadata` — solo standard
library — quindi funziona ovunque Olympus giri e descrive sempre i pacchetti che
questo interprete caricherebbe. I due approcci sono complementari: SBOM nativo
dell'applicazione + SBOM Syft dell'immagine.

## Cosa contiene

- `bomFormat` / `specVersion` (CycloneDX 1.5);
- `metadata.component`: l'applicazione `olympus-security` con versione e PURL;
- un `component` per ogni dipendenza risolta, con `version`, `purl`
  (`pkg:pypi/<nome>@<versione>`) e `licenses` (dal campo License o dai classifier).

I componenti sono **ordinati per nome** e timestamp/serial sono iniettati dal
chiamante, così `--reproducible` produce un documento identico byte-per-byte tra
esecuzioni — utile per diff e attestazioni.

## La chiusura delle dipendenze

Viene percorsa dal `Requires-Dist` della distribuzione radice, seguendo solo i
requisiti **non** vincolati a un extra, a meno che l'extra non sia richiesto
esplicitamente con `--extra`. Così l'SBOM di default copre il runtime che un
`pip install olympus-security` semplice porta con sé; `--extra aegis` lo allarga
al gruppo `aegis`. Le dipendenze dichiarate ma **non installate** in questo
ambiente non vengono attraversate: l'SBOM descrive ciò che è realmente presente.

## Scansione vulnerabilità

La chiusura runtime — **solo** i pacchetti che Olympus porta con sé, non il
bootstrap `pip`/`setuptools`/`wheel` dell'interprete — viene auditata in CI con
**pip-audit** (PyPA) contro il database di advisory:

```python
from olympus.core.sbom import requirements_lines
# name==version, uno per riga, pronte per: pip-audit -r closure.txt
```

Il gate CI `dependency-audit` è **bloccante**: se compare una vulnerabilità nota
in una dipendenza di Olympus, la CI diventa rossa e si aggiorna il pacchetto. Al
momento la chiusura è pulita ("No known vulnerabilities found"). Lo scoping alla
sola chiusura di Olympus evita che vulnerabilità di pacchetti di sistema — che
non sono responsabilità di Olympus — inquinino il risultato.

L'SBOM CycloneDX prodotto è inoltre consumabile da **Grype** (`grype sbom:...`)
per lo stesso scopo sull'immagine/artefatto, complementare a pip-audit.

## In CI

Il job wheel della CI genera l'SBOM dal wheel installato in un ambiente pulito,
ne valida il formato e lo pubblica come artefatto di build (`olympus-sbom`). Un
job separato `dependency-audit` esegue pip-audit sulla chiusura runtime.
