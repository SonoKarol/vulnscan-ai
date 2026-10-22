# VulnScan AI 🛡️

Scanner di sicurezza per siti web che funziona **subito, senza scaricare modelli**: un analista
integrato spiega ogni problema, descrive lo scenario d'attacco e ti dice cosa correggere per primo.
Niente Ollama, niente cloud, niente API key.

Chi vuole testi più ricchi può aggiungere, in modo **facoltativo**, un modello AI locale che gira
dentro il processo Node tramite [llama.cpp](https://github.com/ggml-org/llama.cpp)
([node-llama-cpp](https://node-llama-cpp.withcat.ai)).

## Novità della v2

- **Analista integrato, zero download** — sommario, scenario d’attacco per ogni problema e priorità d’intervento (ordinate per gravità e sforzo, con lo stack rilevato) generati all’istante, in italiano, dai dati reali della scansione.
- **Modello AI opzionale al posto di Ollama** — se lo scarichi (dalla UI o da riga di comando) viene caricato in-process, con accelerazione CUDA / Vulkan / Metal automatica, e usato al posto dell’analista integrato; se fallisce si torna all’analista. La risposta è vincolata da una grammar JSON Schema, quindi sempre valida.
- **Controlli deterministici** — oltre 30 controlli con evidenze reali (header, CSP, TLS, cookie, CORS, redirect HTTPS, `.git`/`.env` esposti, security.txt…) e punteggio riproducibile.
- **Remediation pronte da copiare** per lo stack rilevato (nginx, Apache, Express, Next.js, IIS, Caddy, Cloudflare).
- **Nuova UX** — progresso reale in streaming, report immediato con l’analisi AI che si compone dal vivo, filtri per gravità, storico locale con trend del punteggio, export Markdown / JSON / PDF, tema chiaro/scuro, layout responsive.
- **Sicurezza** — guardia SSRF a livello di socket (resiste al DNS rebinding), backend in ascolto solo su `127.0.0.1`, CSP e header di sicurezza sull’app stessa, font self-hosted.
- **Stack aggiornato** — Node ≥ 22.12, Express 5, React 19, Vite 8, ESM, workspace npm unico.

## Avvio rapido

```bash
npm install                              # installa backend + frontend
cp backend/.env.example backend/.env     # opzionale: i default vanno bene
npm run dev                              # backend :3001 + frontend :5173
```

Apri **http://localhost:5173**: è tutto pronto, non serve scaricare nulla.

### Produzione (un solo processo)

```bash
npm run build && npm start               # tutto su http://localhost:3001
```

## Modello AI opzionale

Non serve per usare l’app. Se vuoi testi più discorsivi premi **“Scarica modello AI (opzionale)”**
nella home oppure lancia `npm run model:download`. Scegli il modello con `AI_MODEL` in `backend/.env`:

| Preset        | Modello        | Download | Quando usarlo |
|---------------|----------------|----------|---------------|
| `leggero`     | Qwen 3.5 0.8B  | ~1 GB    | PC con poca RAM, analisi essenziale |
| `bilanciato`  | Qwen 3.5 4B    | ~3 GB    | **default consigliato** |
| `accurato`    | Qwen 3.5 9B    | ~6 GB    | GPU dedicata o ≥ 16 GB di RAM |

Accetta anche qualsiasi URI Hugging Face (`hf:giladgd/gemma-4-E4B-it-GGUF:Q4_K_M`) o il percorso di un file `.gguf` locale.
`npm run model:download accurato` scarica un preset senza avviare il server.

## Configurazione (`backend/.env`)

| Variabile               | Default                    | Descrizione |
|-------------------------|----------------------------|-------------|
| `PORT` / `HOST`         | `3001` / `127.0.0.1`       | Indirizzo del backend |
| `AI_ENABLED`            | `true`                     | `false` disattiva il modello opzionale (l’analista integrato resta) |
| `AI_MODEL`              | `bilanciato`               | Preset, URI `hf:` o file `.gguf` |
| `AI_MODELS_DIR`         | `./models`                 | Dove salvare i modelli |
| `AI_AUTOLOAD`           | `true`                     | Carica all’avvio il modello, solo se già scaricato |
| `AI_GPU`                | `auto`                     | `auto`, `cuda`, `vulkan`, `metal`, `false` |
| `AI_CONTEXT_SIZE`       | `8192`                     | Contesto del modello (token) |
| `ALLOW_PRIVATE_TARGETS` | `false`                    | Consente di scansionare localhost/LAN (es. il tuo server di sviluppo) |
| `TOR_PROXY`             | `socks5h://127.0.0.1:9150` | Proxy Tor per i siti `.onion` (9150 Tor Browser, 9050 servizio) |

## Architettura

```
frontend/  React 19 + Vite — UI, storico locale, export
backend/
  server.js            Express 5, header di sicurezza, serve frontend/dist
  src/routes/api.js    /api/status, /api/ai/*, /api/scan (stream NDJSON)
  src/scanner/         controlli deterministici, punteggio, remediation per stack
  src/net/http.js      richieste HTTP/Tor, guardia SSRF, analisi TLS
  src/ai/builtin.js    analista integrato (sommario, scenari, priorità) — nessun modello
  src/ai/engine.js     modello opzionale: download → load → coda di inferenza
  src/ai/analyze.js    prompt + JSON Schema per il modello opzionale
  test/                node --test
```

`POST /api/scan` restituisce uno stream di eventi: `step` → `report` (deterministico, subito) →
`ai-progress` (sommario parziale) → `ai` → `done`.

## Test

```bash
npm test
```

## ⚠️ Uso responsabile

Usa VulnScan AI **solo** su sistemi di tua proprietà o con autorizzazione esplicita.
Scansionare siti di terzi senza consenso è illegale in Italia e nella maggior parte dei paesi.
