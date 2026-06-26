# VulnScan AI 🛡️
### 100% gratuito — AI locale con Ollama

Web app di analisi vulnerabilità AI-powered. Nessuna API key, nessun costo, tutto gira sul tuo PC.

## Stack
- **Frontend**: React 18 + Vite
- **Backend**: Node.js + Express
- **AI**: Ollama (Mistral/Llama — locale e gratuito)

## Setup rapido

```bash
# 1. Installa Ollama da https://ollama.com, poi:
ollama pull mistral
ollama serve          # lascia aperto

# 2. Backend
cd backend && npm install && cp .env.example .env && npm run dev

# 3. Frontend (altro terminale)
cd frontend && npm install && npm run dev
```

Apri **http://localhost:5173**

## Funzionalità
- ✅ Analisi 7 header di sicurezza (HSTS, CSP, X-Frame-Options…)
- ✅ Rilevamento server info esposta
- ✅ Report AI con severity, impact e remediation
- ✅ Security score 0-100
- ✅ Badge stato Ollama in tempo reale
- ✅ UI dark minimalista stile terminal
- ✅ Zero costi, zero cloud, zero API key
