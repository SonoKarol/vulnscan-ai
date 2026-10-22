# 🛡️ VulnScan AI — Guida Installazione Windows

Funziona subito: niente Ollama e **nessun modello da scaricare**.

---

## 1. Prerequisiti

### Node.js (22.12 o superiore)
1. Vai su **https://nodejs.org** e scarica la versione **LTS**
2. Esegui l’installer `.msi` lasciando le opzioni di default
3. Verifica nel Prompt dei comandi (`Win + R` → `cmd`):
   ```cmd
   node --version
   ```

---

## 2. Installazione

```cmd
cd C:\Projects\vulnscan-ai
npm install
copy backend\.env.example backend\.env
```

Il file `.env` funziona già così com’è. ✅

---

## 3. Avvio

```cmd
npm run dev
```

Una sola finestra: avvia backend e frontend insieme. Apri **http://localhost:5173** e scansiona:
report, scenari d’attacco e priorità arrivano subito, grazie all’analista integrato.

### Versione “produzione” (un solo processo, nessun server di sviluppo)
```cmd
npm run build
npm start
```
Poi apri **http://localhost:3001**.

---

## (Opzionale) Modello AI per testi più ricchi

Non è necessario. Se lo vuoi, premi **“Scarica modello AI (opzionale)”** nella home oppure lancia
`npm run model:download`. Con una GPU NVIDIA (CUDA) o AMD/Intel (Vulkan) e driver aggiornati
viene accelerato automaticamente. Scegli il modello in `backend\.env`:

| `AI_MODEL=`   | Download | Consigliato per |
|---------------|----------|-----------------|
| `leggero`     | ~1 GB    | PC con 8 GB di RAM o meno |
| `bilanciato`  | ~3 GB    | la maggior parte dei PC ← default |
| `accurato`    | ~6 GB    | GPU dedicata o 16 GB+ di RAM |

Dopo aver cambiato modello riavvia `npm run dev` e scaricalo dalla UI.

---

## Risoluzione problemi

### ❌ “Modello AI non disponibile” / errore di download
→ Riguarda solo il modello opzionale: l’analisi continua con l’analista integrato.
Controlla la connessione a Hugging Face e premi **Riprova**.
Dietro un proxy aziendale scarica il file `.gguf` a mano e imposta `AI_MODEL=C:\percorso\modello.gguf`.

### ❌ L’analisi è lenta
→ Succede solo con il modello opzionale su sola CPU: usa `AI_MODEL=leggero`, oppure
`AI_ENABLED=false` per tornare all’analista integrato (istantaneo).

### ❌ “Target non consentito: indirizzo IP interno”
→ Per sicurezza localhost e la rete locale sono bloccati. Per testare un tuo server di sviluppo
imposta `ALLOW_PRIVATE_TARGETS=true` in `backend\.env` (solo se il backend non è esposto in rete).

### ❌ `npm install` dà errori di rete
```cmd
npm config set registry https://registry.npmjs.org/
npm install
```

---

## 🧅 Siti .onion (opzionale)

1. Avvia **Tor Browser** (https://www.torproject.org) e tienilo aperto → proxy su `127.0.0.1:9150`
   oppure avvia il servizio `tor.exe` → proxy su `127.0.0.1:9050` (imposta `TOR_PROXY=socks5h://127.0.0.1:9050`).
2. Digita un indirizzo `.onion`: l’app verifica Tor e instrada la scansione attraverso la rete Tor.

---

## ⚠️ Note di sicurezza
Usa VulnScan AI **solo** su siti di tua proprietà o con permesso esplicito. Scansionare siti di terzi
senza consenso è illegale in Italia e nella maggior parte dei paesi.
