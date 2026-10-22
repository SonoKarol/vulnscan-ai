# VulnScan AI 🛡️

Scanner di sicurezza per siti web con **modello AI embedded**: l’LLM gira dentro il processo Node
tramite [llama.cpp](https://github.com/ggml-org/llama.cpp) ([node-llama-cpp](https://node-llama-cpp.withcat.ai)).
Niente Ollama, niente cloud, niente API key — dopo il download del modello funziona anche offline.

## Novità della v2

- **AI embedded al posto di Ollama** — il modello GGUF viene scaricato una volta (dalla UI o da riga di comando) e caricato in-process, con accelerazione CUDA / Vulkan / Metal automatica e fallback su CPU.
- **Output AI sempre valido** — la risposta del modello è vincolata da una grammar JSON Schema: niente più “Il modello non ha restituito JSON valido”.
- **Controlli deterministici + AI** — oltre 30 controlli con evidenze reali (header, CSP, TLS, cookie, CORS, redirect HTTPS, `.git`/`.env` esposti, security.txt…) e punteggio riproducibile; l’AI aggiunge sintesi, scenari d’attacco per ogni problema e priorità d’intervento.
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

Apri **http://localhost:5173** e premi **“Scarica modello”** nella card del motore AI
(oppure, prima: `npm run model:download`). La scansione funziona anche senza AI.

### Produzione (un solo processo)

```bash
npm run build && npm start               # tutto su http://localhost:3001
```

## Modelli

Imposta `AI_MODEL` in `backend/.env`:

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
| `AI_ENABLED`            | `true`                     | Disattiva completamente l’AI |
| `AI_MODEL`              | `bilanciato`               | Preset, URI `hf:` o file `.gguf` |
| `AI_MODELS_DIR`         | `./models`                 | Dove salvare i modelli |
| `AI_AUTOLOAD`           | `true`                     | Carica all’avvio il modello già scaricato |
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
  src/ai/engine.js     ciclo di vita del modello (download → load → coda di inferenza)
  src/ai/analyze.js    prompt + JSON Schema per l’analisi
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
