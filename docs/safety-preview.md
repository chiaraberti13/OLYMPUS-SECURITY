# Safety preview di un run pianificato

Prima che un singolo scanner parta, un operatore deve poter rispondere in un
unico punto e in termini chiari alla domanda: **"cosa sto esattamente per
fare?"**. Questo è lo scopo del safety preview (`ROADMAP` `UX-B`).

Modulo interface-agnostic: `olympus.themis.preview`.
Comando: `olympus themis preview`.

## Una sola fonte per tutte le interfacce

Il preview non contiene logica di sicurezza propria: riusa i primitivi già
esistenti, esattamente come `olympus.integrations.activity` è l'unica fonte
della classificazione di rischio.

| Informazione | Da dove arriva |
| --- | --- |
| Esito scope (statico) | `olympus.themis.scope.ensure_allowed` — **nessuna attività di rete** |
| Classe di rischio + spiegazione | `olympus.integrations.activity` (`PASSIVE`/`ACTIVE`/`INTRUSIVE`) |
| Tool esterno | `ScannerSpec.binary` (o marcatore "remote API service") |
| Target normalizzato, budget, output, autorizzazione | il `ThemisRunRequest` pianificato |

Così CLI, TUI e Web control plane mostrano lo **stesso** `SafetyPreview`
(`to_dict()` serializzabile) invece di re-derivare ciascuna la propria risposta,
e il "cosa sto per fare" non può divergere tra interfacce.

## Strettamente offline: lo scope non risolve il DNS

Il controllo di scope è **statico**. `ensure_allowed` valida host/dominio/CIDR
senza contattare nulla, e il preview non risolve mai nomi. Quando la decisione
definitiva richiederebbe la risoluzione a run-time (per bloccare rebinding/SSRF
contro l'indirizzo risolto), il preview lo dichiara onestamente invece di far
credere che il nome sia già autorizzato.

| Esito (`scope_decision`) | Significato | Blocca il lancio? |
| --- | --- | --- |
| `in_scope` | IP letterale autorizzato da host esatto o CIDR. Definitivo offline. | no |
| `resolution_required` | Nome autorizzato per corrispondenza; l'IP risolto è ri-verificato a run-time. | no |
| `out_of_scope` | Target non coperto dallo scope dell'engagement. | **sì** |
| `blocked` | IP non-globale non autorizzato per IP/CIDR (guardrail SSRF). | **sì** |
| `invalid` | Il target non è interpretabile come host, dominio o URL. | **sì** |

## Conferma proporzionata

Il preview espone `requires_confirmation`, il predicato che un'interfaccia usa
per decidere se chiedere una conferma esplicita (`UX-B`):

- run **`active`** o **`intrusive`** non simulati → conferma richiesta;
- run **`passive`** o in **`--simulate`** → nessuna conferma aggiuntiva.

Uno scanner non riconosciuto non è mai sottostimato: default a `ACTIVE`,
`scanner_known=False`, e quindi conferma richiesta.

## Uso da riga di comando

Il comando **non esegue nulla** e non contatta alcun target: è una lettura
offline, scriptabile, da fare prima di accodare o lanciare un job.

```bash
# Riepilogo umano
olympus themis preview nmap --target 10.0.0.5 --scope scope.json --i-am-authorized

# Output machine-readable per la CI
olympus themis preview sqlmap --target app.example.com --kind url \
  --scope scope.json --i-am-authorized --format json
```

I campi derivati dal target passano per `safe_terminal_text`, così un hostname
ostile non può falsificare righe o iniettare sequenze di escape nel terminale
dell'operatore (`SEC-H`).

### Codici di uscita

| Codice | Causa |
| --- | --- |
| `0` | Preview prodotto; lo scope non blocca il lancio (`in_scope` o `resolution_required`). |
| `2` | Uso errato: `--kind`/`--format` non validi, scope file assente o non valido. |
| `3` | Lo scope bloccherebbe il lancio (`out_of_scope`, `blocked` o target `invalid`). |

Il codice `3` è un esito onesto, non un errore del preview: permette a uno
script di ramificare senza interpretare il testo.

## Cosa resta da fare

Questa è la fonte dati e la sua esposizione CLI. L'innesto del preview nel
rendering della TUI e la conferma interattiva in-flow lungo il percorso di
esecuzione restano follow-up tracciati in [`ROADMAP.md`](../ROADMAP.md) sotto
`UX-B`.

## Riferimenti

- Classificazione attività/rischio: [`docs/scanner-maturity.md`](scanner-maturity.md)
- Form derivati dalla CLI (`UX-A`): [`docs/tui.md`](tui.md)
- Dati ostili dai target (`SEC-H`): [`ROADMAP.md`](../ROADMAP.md)
