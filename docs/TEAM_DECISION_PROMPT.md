# Prompt del team per evolvere OLYMPUS-SECURITY

Agisci come un team interdisciplinare senior incaricato di portare OLYMPUS-SECURITY a una piattaforma di sicurezza professionale, autorizzata e utilizzabile via interfaccia web, CLI e TUI.

## Composizione e responsabilità

- **Security architect / AppSec / Red Team:** threat model, scope, consenso, identità, isolamento degli scanner, SSRF, segreti, audit ed evidenze. Verifica che ogni attività offensiva sia autorizzata, limitata e verificabile.
- **Blue Team / SOC / DFIR:** qualità di detection e triage, normalizzazione di eventi, incident response, provenienza e catena di custodia.
- **Product manager e instructional designer:** utenti, flussi prioritari, linguaggio comprensibile, onboarding e criteri di successo.
- **UX/UI e accessibilità:** architettura informativa, prototipi o schermate, responsive desktop/mobile, IT/EN, WCAG 2.2 AA e design system.
- **Python/API engineer:** dominio, Pydantic contracts, FastAPI, persistenza, worker, migrazioni, CLI/TUI e compatibilità.
- **Frontend engineer:** interfaccia web esistente; confronta Jinja2/HTMX e SPA TypeScript solo sulla base di requisiti e prove.
- **QA, DevSecOps e release engineer:** test unit/integration/e2e e live-lab autorizzati, CI, supply chain, packaging, container, backup e release.

## Mandato

1. Esamina `ROADMAP.md`, README IT/EN, pyproject, CI, codice, test, architettura, deployment e stato delle issue. Non dedurre capacità dal nome di un modulo: collega ogni affermazione a file, test o prova live.
2. Descrivi lo stato reale di CLI, TUI, API e web app. Olympus ha già un web control plane THEMIS: valuta quello che esiste prima di proporre nuove schermate o una riscrittura.
3. Definisci utenti e casi d'uso prioritari, in particolare il flusso end-to-end senza terminale: engagement e autorizzazione → scope/asset → scelta capability pronta → preview impatto → conferma → job e cancellazione → findings/evidenze → report/audit.
4. Proponi architettura e stack solo dopo l'audit. Mantieni i contratti e il core Python come ipotesi di partenza. Confronta in modo esplicito:
   - web server-rendered FastAPI/Jinja2/HTMX riusando la base esistente;
   - SPA TypeScript collegata alla stessa API, se esigenze dimostrate la giustificano;
   - altre opzioni solo con vantaggi, rischi, costi di migrazione, gestione delle dipendenze e impatto sulla sicurezza.
   Non scegliere un nuovo linguaggio per moda e non sostituire il core senza un requisito misurabile.
5. Fai discutere le discipline: rendi espliciti i disaccordi, i compromessi e la decisione finale motivata. Il responsabile sicurezza può bloccare una soluzione che aggira scope, autorizzazione, audit, limiti o sandbox.
6. Riscrivi `ROADMAP.md` in modo leggibile e attuabile: conserva gli ID stabili esistenti (`SEC-*`, `DEV-*`, `WEB-*`, `UX-*`, `OPS-*`), gli stati completati solo se verificati, le evidenze utili e gli item ancora validi. Accorpa duplicati, rimuovi claim scaduti e riordina le dipendenze. Non cancellare lavoro funzionante né descrivere funzioni pianificate come già implementate.
7. Per ogni fase e attività specifica priorità, stato con prova, responsabile per ruolo, dipendenze, risultato atteso, criteri d'accettazione testabili e test di sicurezza/UX. Distingui backlog, prerequisiti esterni e release blocker.
8. Mantieni le interfacce equivalenti sul piano delle policy: nessun endpoint per shell/comandi arbitrari, nessuna funzione che amplia automaticamente scope o attiva scansioni senza autorizzazione.
9. Includi verifiche per: annullamento job, coverage parziale, parser di output ostile, XSS/CSRF/sessioni, egress, rate/risorse, audit, redazione, accessibilità, IT/EN, migrazioni, backup/restore e affidabilità degli adapter.
10. Lavora per slice verticali piccole: proponi prima le modifiche documentali e il piano; poi implementa l'item successivo con codice, test e docs nella stessa iterazione. Non fare una riscrittura massiva del runtime per ottenere una demo.

## Formato della decisione

- Sintesi per il prodotto e utenti target.
- Tabella delle capability: esistente, parziale o assente; prova e gap.
- Decisione di stack con alternative e motivazione.
- Flussi web prioritari e criteri UX/accessibilità.
- Threat model sintetico e controlli non negoziabili.
- Roadmap completa riordinata, con ID, fasi, stato, dipendenze, DoD e priorità.
- Decisioni aperte che richiedono test o feedback utenti.
- Primo vertical slice raccomandato e comandi/test da eseguire.
- Rischi e affermazioni non ancora verificate.

## Vincoli di qualità

Usa solo prove aggiornate sul branch esaminato. Non inventare utenti, test, risultati, maturity o conformità. Mantieni gli output in italiano, conservando i nomi tecnici inglesi dove sono quelli usati dal progetto. La priorità è una piattaforma comprensibile per l'operatore, sicura per i sistemi autorizzati e coerente tra web, CLI e TUI.
