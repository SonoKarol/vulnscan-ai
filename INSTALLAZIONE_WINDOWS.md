# 🛡️ VulnScan AI — Guida Installazione Windows

L’AI gira **dentro l’app**: non serve più installare né avviare Ollama.

---

## 1. Prerequisiti

### Node.js (22.12 o superiore)
1. Vai su **https://nodejs.org** e scarica la versione **LTS**
2. Esegui l’installer `.msi` lasciando le opzioni di default
3. Verifica nel Prompt dei comandi (`Win + R` → `cmd`):
   ```cmd
   node --version
   ```

### (Opzionale) Accelerazione GPU
- **NVIDIA**: aggiorna i driver — CUDA viene usato automaticamente.
- **AMD / Intel**: con driver aggiornati viene usato Vulkan.
- Senza GPU il modello gira su CPU (più lento ma funzionante).

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

Una sola finestra: avvia backend e frontend insieme. Apri **http://localhost:5173**.

Al primo avvio, nella card **“Installa il modello AI”** premi **Scarica modello**
(~3 GB con il preset consigliato, una volta sola). In alternativa, da terminale:

```cmd
npm run model:download
```

Quando la card mostra **“Motore AI pronto”** l’analisi AI è attiva.
Le scansioni funzionano anche prima: ottieni subito il report dei controlli automatici.

### Versione “produzione” (un solo processo, nessun server di sviluppo)
```cmd
npm run build
npm start
```
Poi apri **http://localhost:3001**.

---

## Scegliere il modello

In `backend\.env`:

| `AI_MODEL=`   | Download | Consigliato per |
|---------------|----------|-----------------|
| `leggero`     | ~1 GB    | PC con 8 GB di RAM o meno |
| `bilanciato`  | ~3 GB    | la maggior parte dei PC ← default |
| `accurato`    | ~6 GB    | GPU dedicata o 16 GB+ di RAM |

Dopo aver cambiato modello riavvia `npm run dev` e scaricalo dalla UI.

---

## Risoluzione problemi

### ❌ “Il modello non è disponibile” / errore di download
→ Controlla la connessione a Hugging Face e premi **Riprova**.
Dietro un proxy aziendale scarica il file `.gguf` a mano e imposta `AI_MODEL=C:\percorso\modello.gguf`.

### ❌ L’analisi AI è lenta
→ Normale su sola CPU con modelli grandi: usa `AI_MODEL=leggero`, oppure verifica che la card
mostri l’accelerazione GPU. Il report base è comunque disponibile subito.

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
