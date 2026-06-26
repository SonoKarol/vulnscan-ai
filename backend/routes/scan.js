const express = require('express');
const axios   = require('axios');
const dns     = require('dns').promises;
const net     = require('net');
const { SocksProxyAgent } = require('socks-proxy-agent');

const router = express.Router();

const OLLAMA_URL  = process.env.OLLAMA_URL  || 'http://localhost:11434';
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'mistral';
const TOR_PROXY   = process.env.TOR_PROXY   || 'socks5://127.0.0.1:9150';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function normalizeUrl(raw) {
  try {
    if (!/^https?:\/\//i.test(raw)) raw = 'http://' + raw;
    return new URL(raw).href;
  } catch {
    throw new Error('URL non valido: ' + raw);
  }
}

function isOnion(url) {
  try { return new URL(url).hostname.endsWith('.onion'); }
  catch { return false; }
}

// ─── SSRF guard ──────────────────────────────────────────────────────────────
// Lo scanner fa richieste server-side verso URL forniti dall'utente: blocca gli
// indirizzi interni (loopback, RFC-1918, link-local, metadata cloud) per evitare
// che il backend venga usato per raggiungere risorse private della rete.

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 10) return true;
    if (a === 127) return true;                       // loopback
    if (a === 0) return true;
    if (a === 169 && b === 254) return true;          // link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // RFC-1918
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    return false;
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::') return true;
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // ULA
    if (lower.startsWith('fe80')) return true;        // link-local
    // IPv4-mapped (::ffff:a.b.c.d)
    const mapped = lower.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIp(mapped[1]);
    return false;
  }
  return false;
}

// Verifica che l'host pubblico non risolva a un IP interno. I servizi .onion
// non passano dal DNS di sistema (risolti da Tor), quindi vengono saltati.
async function assertPublicTarget(url) {
  if (isOnion(url)) return;
  const hostname = new URL(url).hostname;
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) throw new Error('Target non consentito: indirizzo IP interno');
    return;
  }
  let addrs;
  try {
    addrs = await dns.lookup(hostname, { all: true });
  } catch {
    throw new Error('Impossibile risolvere il dominio: ' + hostname);
  }
  if (addrs.some(a => isPrivateIp(a.address))) {
    throw new Error('Target non consentito: il dominio risolve a un indirizzo interno');
  }
}

function buildAxiosConfig(url, extraOptions = {}) {
  const config = {
    timeout: isOnion(url) ? 30000 : 10000, // Tor è più lento
    maxRedirects: 0,                       // li seguiamo a mano, ri-validando ogni hop (anti-SSRF)
    validateStatus: () => true,
    headers: { 'User-Agent': 'VulnScan-AI/1.0 (Security Audit Tool)' },
    ...extraOptions,
  };
  if (isOnion(url)) {
    config.httpsAgent = new SocksProxyAgent(TOR_PROXY);
    config.httpAgent  = new SocksProxyAgent(TOR_PROXY);
    config.proxy      = false; // disabilita proxy di axios, usiamo l'agent
  }
  return config;
}

async function checkTorStatus() {
  try {
    // Verifica che Tor funzioni chiedendo la check page di Tor Project
    const agent = new SocksProxyAgent(TOR_PROXY);
    const res = await axios.get('https://check.torproject.org/api/ip', {
      httpAgent: agent, httpsAgent: agent, proxy: false, timeout: 10000,
    });
    return res.data?.IsTor === true;
  } catch {
    return false;
  }
}

async function fetchSiteInfo(url) {
  const result = {
    url, reachable: false, statusCode: null,
    headers: {}, responseTime: null, serverInfo: {},
    isOnion: isOnion(url), errors: [],
  };

  const start = Date.now();
  try {
    let current = url;
    let resp;
    for (let hop = 0; hop <= 5; hop++) {
      await assertPublicTarget(current);
      resp = await axios.get(current, buildAxiosConfig(current));
      if (resp.status >= 300 && resp.status < 400 && resp.headers['location']) {
        if (hop === 5) throw new Error('Troppi redirect (>5)');
        current = new URL(resp.headers['location'], current).href; // risolve location relativi
        continue;
      }
      break;
    }
    result.url          = current;
    result.reachable    = true;
    result.statusCode   = resp.status;
    result.headers      = resp.headers;
    result.responseTime = Date.now() - start;
    result.serverInfo   = {
      server:      resp.headers['server']       || null,
      poweredBy:   resp.headers['x-powered-by'] || null,
      contentType: resp.headers['content-type'] || null,
    };
  } catch (err) {
    result.errors.push(err.message);
  }
  return result;
}

function analyzeHeaders(headers) {
  const checks = [
    { header: 'strict-transport-security',  name: 'HSTS',                  description: 'Forza connessioni HTTPS' },
    { header: 'content-security-policy',    name: 'Content-Security-Policy',description: 'Previene XSS e injection attacks' },
    { header: 'x-frame-options',            name: 'X-Frame-Options',        description: 'Previene clickjacking' },
    { header: 'x-content-type-options',     name: 'X-Content-Type-Options', description: 'Previene MIME-type sniffing' },
    { header: 'referrer-policy',            name: 'Referrer-Policy',        description: 'Controlla le informazioni nel Referer header' },
    { header: 'permissions-policy',         name: 'Permissions-Policy',     description: 'Controlla accesso a funzionalità browser' },
    { header: 'x-xss-protection',           name: 'X-XSS-Protection',       description: 'Protezione XSS browser (legacy)' },
  ];
  return checks.map(c => ({
    header: c.header, name: c.name, description: c.description,
    value:  headers[c.header] || null,
    status: headers[c.header] ? 'present' : 'missing',
  }));
}

async function analyzeWithOllama(siteData, headerChecks) {
  const missingHeaders = headerChecks.filter(h => h.status === 'missing');
  const presentHeaders  = headerChecks.filter(h => h.status === 'present');
  const onionNote = siteData.isOnion
    ? '\nNOTA: Questo è un sito .onion sulla rete Tor. Considera vulnerabilità specifiche dei servizi nascosti come: deanonymization, correlazione del traffico, configurazioni errate che espongono l\'IP reale del server.'
    : '';

  const prompt = `Sei un esperto di sicurezza informatica e penetration tester. Analizza questi dati di un sito web e produci un report professionale in formato JSON.${onionNote}

URL: ${siteData.url}
Tipo: ${siteData.isOnion ? 'Servizio nascosto Tor (.onion)' : 'Sito web standard'}
Status HTTP: ${siteData.statusCode}
Tempo risposta: ${siteData.responseTime}ms
Server esposto: ${siteData.serverInfo.server || 'non rilevato'}
X-Powered-By: ${siteData.serverInfo.poweredBy || 'non rilevato'}

Header di sicurezza PRESENTI (${presentHeaders.length}):
${presentHeaders.map(h => `- ${h.name}: ${h.value}`).join('\n') || 'Nessuno'}

Header di sicurezza MANCANTI (${missingHeaders.length}):
${missingHeaders.map(h => `- ${h.name}: ${h.description}`).join('\n') || 'Nessuno'}

Per ogni vulnerabilità trovata devi fornire:
1. Una descrizione tecnica
2. Come un attaccante reale potrebbe sfruttarla (scenario concreto, passo per passo)
3. Come il developer può correggerla (fix concreto con esempio di codice o configurazione)

Rispondi SOLO con un oggetto JSON valido, senza markdown, senza backtick, senza testo aggiuntivo:
{
  "summary": "sommario della postura di sicurezza in 2-3 frasi",
  "score": <numero 0-100>,
  "risk_level": "<critical|high|medium|low>",
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "title": "titolo breve della vulnerabilità",
      "severity": "<critical|high|medium|low|info>",
      "category": "categoria",
      "description": "descrizione tecnica dettagliata",
      "exploit_scenario": "scenario realistico passo per passo: come un attaccante sfrutterebbe questa vulnerabilità, strumenti usati, risultato finale",
      "remediation": "come risolvere con esempio pratico di configurazione o codice",
      "references": ["url a CVE, OWASP o documentazione ufficiale"]
    }
  ],
  "positive_findings": [
    { "title": "cosa è configurato bene", "description": "perché è positivo" }
  ],
  "recommendations": ["raccomandazione 1", "raccomandazione 2", "raccomandazione 3"]
}`;

  const response = await axios.post(`${OLLAMA_URL}/api/generate`, {
    model: OLLAMA_MODEL,
    prompt,
    stream: false,
    options: { temperature: 0.1 },
  }, { timeout: 120000 });

  if (typeof response.data?.response !== 'string') {
    throw new Error('Risposta AI non valida — verifica che il modello sia installato (ollama pull ' + OLLAMA_MODEL + ')');
  }
  const raw = response.data.response.trim();
  const jsonMatch = raw.match(/\{[\s\S]*\}/);
  if (!jsonMatch) throw new Error('Il modello AI non ha restituito JSON valido');
  return normalizeReport(JSON.parse(jsonMatch[0]));
}

// Il report arriva da un LLM locale: normalizza i campi prima di inviarlo al
// frontend, così un campo mancante non fa crashare la UI.
const VALID_SEVERITY = ['critical', 'high', 'medium', 'low', 'info'];
function normalizeReport(report) {
  const r = report && typeof report === 'object' ? report : {};
  const vulns = Array.isArray(r.vulnerabilities) ? r.vulnerabilities : [];
  return {
    summary: typeof r.summary === 'string' ? r.summary : 'Nessun sommario disponibile.',
    score: Number.isFinite(r.score) ? r.score : 0,
    risk_level: VALID_SEVERITY.includes(r.risk_level) ? r.risk_level : 'info',
    vulnerabilities: vulns.map((v, i) => ({
      id: v.id || `VULN-${String(i + 1).padStart(3, '0')}`,
      title: v.title || 'Vulnerabilità senza titolo',
      severity: VALID_SEVERITY.includes(v.severity) ? v.severity : 'info',
      category: v.category || 'generale',
      description: v.description || '',
      exploit_scenario: v.exploit_scenario || '',
      remediation: v.remediation || '',
      references: Array.isArray(v.references) ? v.references : [],
    })),
    positive_findings: Array.isArray(r.positive_findings) ? r.positive_findings : [],
    recommendations: Array.isArray(r.recommendations) ? r.recommendations : [],
  };
}

// ─── Health checks ────────────────────────────────────────────────────────────

router.get('/health', async (req, res) => {
  // Ollama
  let ollamaStatus = 'offline';
  try {
    await axios.get(`${OLLAMA_URL}/api/tags`, { timeout: 3000 });
    ollamaStatus = 'online';
  } catch {}

  // Tor
  let torStatus = 'offline';
  try {
    const isTor = await checkTorStatus();
    torStatus = isTor ? 'online' : 'offline';
  } catch {}

  res.json({
    ollama: ollamaStatus,
    tor:    torStatus,
    model:  OLLAMA_MODEL,
  });
});

// ─── Scan ────────────────────────────────────────────────────────────────────

router.post('/', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL obbligatorio' });

  try {
    const normalizedUrl = normalizeUrl(url);
    const onion = isOnion(normalizedUrl);

    // Se è .onion verifica che Tor sia attivo
    if (onion) {
      const torOk = await checkTorStatus();
      if (!torOk) {
        return res.status(503).json({
          error: 'Tor non raggiungibile',
          details: ['Avvia Tor Browser o il servizio Tor prima di scansionare siti .onion'],
        });
      }
    }

    const siteData = await fetchSiteInfo(normalizedUrl);

    if (!siteData.reachable) {
      return res.status(422).json({
        error: onion
          ? 'Sito .onion non raggiungibile — potrebbe essere offline o l\'indirizzo non è corretto'
          : 'Sito non raggiungibile',
        details: siteData.errors,
      });
    }

    const headerChecks = analyzeHeaders(siteData.headers);
    const aiReport     = await analyzeWithOllama(siteData, headerChecks);

    res.json({
      scannedAt:    new Date().toISOString(),
      target:       normalizedUrl,
      isOnion:      onion,
      responseTime: siteData.responseTime,
      statusCode:   siteData.statusCode,
      serverInfo:   siteData.serverInfo,
      headerChecks,
      ...aiReport,
    });
  } catch (err) {
    console.error('[SCAN ERROR]', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
