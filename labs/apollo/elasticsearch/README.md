# BLUE-2 · Consegna a Elasticsearch

Il laboratorio avvia un nodo Elasticsearch 8.19.0 temporaneo su Linux, in ascolto
su loopback. Apollo invia all'indice `olympus-blue2` i tre alert nativi di BLUE-1
attraverso `deliver_alerts` e l'adapter HTTPS. Il certificato include l'indirizzo
IP del nodo. La chiave di scrittura scade dopo 15 minuti e ha il privilegio
`create_doc` sul solo indice del laboratorio.

La copia di `alerts.json` proviene dal [collaudo Windows originale](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/44756398445).
Lo SHA-256 dello ZIP originale è `71293801d1b97971627b51d06eeb26f44a15f56e0efb51c2129655093b93b285`.
Lo script verifica anche il digest del singolo file prima dell'invio.

Il test controlla la ricevuta 201 di ogni creazione e la ricevuta 409 di ogni
duplicato al secondo invio. Rilegge i tre documenti mediante `_mget`, confronta
gli identificativi e l'intero contenuto ECS, quindi aggiorna la visibilità
dell'indice con `_refresh` e verifica che `_count` restituisca tre.

Per ripetere il test con Olympus installato, impostare `ES_HOME` sul percorso
assoluto di una distribuzione Elasticsearch appena estratta e avviare dalla
radice del repository:

```bash
bash labs/apollo/elasticsearch/run.sh
```

Il workflow [Apollo Elasticsearch lab](../../../.github/workflows/apollo-elasticsearch-lab.yml)
verifica lo SHA-512 della distribuzione e pubblica l'esito nel log del job.
Lo script chiude il nodo e rimuove dati e credenziali temporanei al termine.
