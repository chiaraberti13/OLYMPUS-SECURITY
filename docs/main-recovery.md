# Verifica e ripristino di main

Dopo ogni merge, apri le esecuzioni di GitHub Actions filtrate per branch `main`.
Verifica che l'evento sia `push` e che lo SHA completo corrisponda al commit
effettivamente integrato. Controlla CI e CodeQL e, se la modifica riguarda
l'immagine scanner, anche il relativo build e smoke test.

Registra nella verifica di rilascio lo SHA, i link ai run e i loro esiti.
Qualifica lo SHA come noto-buono solo a verifiche concluse. Il registro parte
vuoto finché non viene raccolta questa evidenza.

| SHA su main | CI | CodeQL | Scanner image, se applicabile |
| --- | --- | --- | --- |

## Ripristino

1. Individua il commit che ha introdotto il problema e consulta l'ultimo SHA
   noto-buono. Conserva il link al run fallito.
2. Crea un branch dall'ultima versione di `main`. Esegui `git revert <sha>`
   per un commit normale oppure `git revert -m 1 <sha>` per un merge,
   dopo aver verificato che il primo parent sia il precedente tip di `main`.
3. Apri una PR con il motivo, lo SHA ripristinato e i link alle esecuzioni.
   Dopo l'approvazione e i check richiesti, unisci la PR e ripeti la verifica
   post-merge sullo SHA del ripristino.
4. Per esercitare la procedura, aggiungi e poi annulla una modifica innocua
   su un branch di prova. Registra il diff finale e gli esiti della CI senza
   unire la PR di esercitazione.
