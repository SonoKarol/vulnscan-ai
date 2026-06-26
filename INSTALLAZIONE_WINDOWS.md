# 🛡️ VulnScan AI — Guida Installazione Windows
## 100% Gratuito — AI locale con Ollama

---

## Prerequisiti (tutti gratuiti)

### 1. Installa Node.js
1. Vai su **https://nodejs.org**
2. Scarica la versione **LTS**
3. Esegui l'installer `.msi` (lascia tutto di default)
4. Verifica aprendo il Prompt dei comandi (`Win + R` → `cmd`):
   ```
   node --version
   npm --version
   ```

### 2. Installa Ollama (AI locale)
1. Vai su **https://ollama.com**
2. Clicca **Download for Windows**
3. Esegui l'installer
4. Al termine, apri il Prompt dei comandi e scarica il modello AI:
   ```
   ollama pull mistral
   ```
   *(scarica ~4GB, fallo una volta sola)*

5. Avvia il server AI locale:
   ```
   ollama serve
   ```
   Lascia questa finestra aperta — è il "cervello" dell'app.

> 💡 **Modelli alternativi** (se il tuo PC è lento):
> - `ollama pull llama3.2:1b` — molto leggero (~1GB)
> - `ollama pull mistral` — bilanciato (~4GB) ← consigliato
> - `ollama pull llama3.1:8b` — più accurato (~5GB)
>
> Se usi un modello diverso, aggiorna `OLLAMA_MODEL` nel file `.env`

---

## Installazione del Progetto

### Passo 1 — Estrai i file
- Clic destro su `vulnscan-ai.zip` → **Estrai tutto...**
- Scegli una cartella, es. `C:\Projects\vulnscan-ai`

### Passo 2 — Backend
Apri il Prompt dei comandi:
```cmd
cd C:\Projects\vulnscan-ai\backend
npm install
copy .env.example .env
```
Il file `.env` non richiede modifiche — Ollama gira in locale senza API key. ✅

### Passo 3 — Frontend
Apri un **secondo** Prompt dei comandi:
```cmd
cd C:\Projects\vulnscan-ai\frontend
npm install
```

---

## Avvio dell'applicazione

Hai bisogno di **3 finestre aperte** (dopo la prima configurazione, Ollama parte da solo):

| Finestra | Comando | Cosa fa |
|----------|---------|---------|
| 1 | `ollama serve` | Avvia il motore AI |
| 2 | `cd backend && npm run dev` | Avvia il backend |
| 3 | `cd frontend && npm run dev` | Avvia il frontend |

Poi apri il browser su: **http://localhost:5173**

Se Ollama è avviato correttamente, vedrai il badge verde **"Ollama online — AI pronta"** nella pagina.

---

## Risoluzione Problemi Comuni

### ❌ "ollama non è riconosciuto"
→ Riavvia il PC dopo l'installazione di Ollama.

### ❌ `ollama pull mistral` è lentissimo
→ Normale, scarica ~4GB. Fallo una volta sola con connessione stabile.

### ❌ Badge rosso "Ollama offline"
→ Hai dimenticato di avviare `ollama serve` nella prima finestra CMD.

### ❌ "npm install" dà errori di rete
→ Prova:
```cmd
npm config set registry https://registry.npmjs.org/
npm install
```

### ❌ La scansione impiega troppo
→ Normale per la prima esecuzione — il modello si carica in memoria (~15-30 sec).
   Le scansioni successive saranno più veloci.

### ❌ Errore JSON dal modello
→ Il modello ha risposto in modo non strutturato. Riprova la scansione.
   Se persiste, considera di usare `llama3.1:8b` (più preciso).

---

## Per fermare tutto
- In ogni finestra CMD: `Ctrl + C`
- Per fermare Ollama completamente: chiudi la finestra o `Ctrl + C`

---

## ⚠️ Note di sicurezza
Usa VulnScan AI **solo** su siti di tua proprietà o con permesso esplicito. Scansionare siti di terzi senza consenso è illegale in Italia e nella maggior parte dei paesi.

---

## 🧅 Supporto Siti .onion (opzionale)

Per scansionare servizi nascosti sulla rete Tor hai bisogno di Tor attivo sul tuo PC.

### Opzione A — Tor Browser (più semplice)
1. Scarica **Tor Browser** da **https://www.torproject.org**
2. Installalo e avvialo
3. Tienilo aperto mentre usi VulnScan AI
4. Il proxy SOCKS5 sarà automaticamente su `127.0.0.1:9150`

### Opzione B — Tor come servizio (avanzata)
1. Scarica **Tor Expert Bundle** da https://www.torproject.org/download/tor/
2. Estrai e avvia da CMD:
   ```cmd
   tor.exe
   ```
3. Attendi il messaggio `Bootstrapped 100% (done): Done`

### Verifica
Nella pagina principale di VulnScan AI vedrai il badge:
- 🟢 **Tor — rete Tor attiva** → pronto per .onion
- 🔴 **Tor — richiesto per .onion** → avvia Tor Browser

### Note sui siti .onion
- I tempi di risposta sono più lenti (10-30 sec) — è normale
- Non tutti i siti .onion sono sempre online
- Assicurati di avere il permesso prima di scansionare qualsiasi sito
