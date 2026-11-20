# BLUE-1 · Validazione su Windows Server 2022

Il 20 novembre 2026 Apollo ha acquisito i quattro EventID in esame da una VM Windows effimera di GitHub Actions con Sysmon e auditing Security attivi. Il parser e le regole provengono dal commit `d5901eda1adf7c3e5bb076a8ffaaf43bf9951400`. Il laboratorio isola il collaudo su un branch dedicato.

## Esiti prima della correzione

| Origine | EventID | Record ID (secondo run) | Indicatore nativo | Regola distribuita |
|---|---:|---:|---|---|
| Sysmon | 2 | 13 | `evil.exe` | APL-SYSMON-TIMESTOMP ha generato un alert |
| Sysmon | 17 | 15 | `\evilc2-pipe` | APL-SYSMON-NAMED-PIPE-C2 ha mancato il caso positivo |
| Sysmon | 18 | 16 | `\evilc2-pipe` | Acquisito. Il pacchetto non include una regola per la connessione |
| Security | 4698 | 1565651 | `\UpdaterTask` | APL-SECURITY-SCHEDULED-TASK ha mancato il caso positivo |

Il workflow acquisisce gli eventi con Get-WinEvent, mantiene l'XML nativo e proietta i campi nominati in NDJSON. Il confronto indipendente tra XML, proiezione e output del parser ha confermato provider, canale e RecordID nella proiezione, tipo di evento, timestamp UTC alla precisione del parser e valori degli attributi pertinenti nell'output. Per il secondo run, il controllo positivo usa un programma innocuo compilato sul runner con il nome richiesto dalla regola. Il programma modifica solo la data di creazione del file temporaneo di prova.

Entrambi i run hanno acquisito quattro eventi con zero scarti. Il primo, con PowerShell come processo autore dell'evento 2, ha generato zero alert. Il secondo ha generato un alert con le nove regole distribuite. Sullo stesso identico `events.ndjson` del secondo run, una copia diagnostica delle regole con i soli valori `pipe_name` e `task_name` prefissati con la barra inversa ha generato tutti e tre gli alert previsti. Il confronto esatto dei due nomi spiega i due falsi negativi. La copertura dimostrata si limita agli esempi esercitati.

## Evidenze

- [Primo run](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/44751503040) · SHA-256 dello ZIP `1ad646c16be0a76caca52d7fbec5a4a0e2fc22f01a24ab7c0ff00056bcff5eea`.
- [Secondo run](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/44751739677) · [workflow eseguito](https://github.com/chiaraberti13/OLYMPUS-SECURITY/blob/999f93eeb575d7f81af232b71072f52966b4520b/.github/workflows/apollo-windows-lab.yml) · SHA-256 dello ZIP `576b053e866a9dd62a6d609970d798b159cd8e1ed53a4547d9ca161219ce3b8d`.
- Entrambi gli archivi contengono quattro XML, `windows.jsonl`, `events.ndjson` e `alerts.json`. I digest sono stati verificati dopo il download. Scadenza degli artefatti GitHub il 27 novembre 2026.

## Verifica delle regole corrette

Il replay dell'archivio del secondo run, verificato tramite SHA-256, ha acquisito quattro eventi con zero scarti. Le nove regole distribuite con la correzione hanno generato tre alert distinti: `APL-SYSMON-TIMESTOMP`, `APL-SYSMON-NAMED-PIPE-C2` e `APL-SECURITY-SCHEDULED-TASK`. Il workflow Windows controlla questo insieme esatto su eventi nuovi per ogni PR che modifica le regole o il parser.

## Replay indipendente

Dal [corpus EVTX-ATTACK-SAMPLES al commit verificato](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/tree/4ceed2f4706daf601c212a8f91c113dd85349a2c) sono stati estratti cinque record dei quattro EventID con python-evtx 0.8.1, preservando i nomi XML di EventData. Apollo ha importato cinque eventi con zero scarti e zero alert. I timestamp, i tipi e i campi selezionati sono stati confrontati con i record sorgente.

| File EVTX | EventID e conteggi | SHA-256 |
|---|---|---|
| Defense Evasion/sysmon_2_11_evasion_timestomp_MACE.evtx | 2 × 1 | `1fd461647854d19cf9c813a419ffc728522507777e76d7a32150e58e746d43d6` |
| Credential Access/sysmon17_18_kekeo_tsssp_default_np.evtx | 17 × 1, 18 × 2 | `5784342008a619ae910f88fe435bc30fc372399f14405c6265dbce8c9b578838` |
| Execution/temp_scheduled_task_4698_4699.evtx | 4698 × 1 | `a7decf0fbabc340e37de7e7c39fddd5398a7106a4f6acded0ea1d2ffa6bf8b70` |
