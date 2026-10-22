import { engine } from './engine.js';

const MAX_FOCUS = 8;
// I limiti di lunghezza della grammar garantiscono che l'output termini sempre
// entro maxTokens (al peggio 1 token per carattere), anche con modelli piccoli.
const LIMITS = { summary: 700, scenario: 400, priority: 200, priorities: 5 };

const SYSTEM_PROMPT = `Sei un penetration tester senior che scrive report di sicurezza per sviluppatori italiani.
Rispondi sempre in italiano, in modo concreto, tecnico e conciso.
Basati esclusivamente sui dati della scansione: non inventare vulnerabilità, CVE, versioni, percorsi o URL che non compaiono nei dati.
Le tue spiegazioni servono a scopo difensivo: descrivi gli scenari d'attacco a livello concettuale, senza payload pronti all'uso.`;

function describe(report) {
  const lines = [
    `Sito: ${report.finalUrl}`,
    `Tipo: ${report.isOnion ? 'servizio nascosto Tor (.onion)' : report.isHttps ? 'sito HTTPS' : 'sito solo HTTP'}`,
    `Stato HTTP: ${report.statusCode} · tempo di risposta ${report.responseTime} ms`,
    `Server: ${report.tech.server || 'non dichiarato'} · X-Powered-By: ${report.tech.poweredBy || 'assente'}${report.tech.generator ? ` · CMS: ${report.tech.generator}` : ''}`,
    `Stack rilevato: ${report.tech.stacks.join(' + ') || 'non determinabile'}`,
  ];
  if (report.tls && !report.tls.error) {
    lines.push(`TLS: ${report.tls.protocol}, certificato ${report.tls.authorized ? 'valido' : 'NON valido'} emesso da ${report.tls.issuer}, scade tra ${report.tls.daysLeft} giorni`);
  }
  lines.push(`Punteggio deterministico: ${report.score}/100 (voto ${report.grade})`, '');
  lines.push(`Problemi rilevati (${report.findings.length}):`);
  for (const f of report.findings) {
    lines.push(`- [${f.id}] gravità ${f.severity} · ${f.title}${f.evidence ? ` — evidenza: ${f.evidence}` : ''}`);
  }
  if (!report.findings.length) lines.push('- nessuno');
  if (report.positives.length) {
    lines.push('', 'Elementi configurati bene:');
    for (const p of report.positives) lines.push(`- ${p.title}`);
  }
  return lines.join('\n');
}

function buildRequest(report) {
  const focus = report.findings.filter(f => f.severity !== 'info').slice(0, MAX_FOCUS);
  const properties = {
    summary: { type: 'string', minLength: 40, maxLength: LIMITS.summary },
  };
  if (focus.length) {
    properties.scenarios = {
      type: 'object',
      properties: Object.fromEntries(focus.map(f => [f.id, { type: 'string', minLength: 20, maxLength: LIMITS.scenario }])),
    };
  }
  properties.priorities = { type: 'array', items: { type: 'string', minLength: 10, maxLength: LIMITS.priority }, minItems: 1, maxItems: LIMITS.priorities };
  const maxTokens = 300 + LIMITS.summary + focus.length * (LIMITS.scenario + 30) + LIMITS.priorities * (LIMITS.priority + 10);

  const tasks = [
    '"summary": 2-3 frasi sulla postura di sicurezza complessiva del sito, citando i rischi più rilevanti e come si collegano tra loro.',
  ];
  if (focus.length) {
    tasks.push(`"scenarios": per ciascun id (${focus.map(f => f.id).join(', ')}) uno scenario d'attacco realistico in massimo 2 frasi: chi attacca, in che condizioni e cosa ottiene, calato sul contesto di questo sito.`);
  }
  tasks.push('"priorities": da 3 a 5 azioni ordinate per rapporto impatto/sforzo, ognuna una frase imperativa e specifica (es. "Abilita HSTS su nginx con max-age di un anno").');
  if (report.isOnion) {
    tasks.push('Trattandosi di un servizio .onion, considera anche i rischi di deanonimizzazione del server (header che rivelano infrastruttura, IP o software).');
  }

  const prompt = `${describe(report)}

Compiti — restituisci un oggetto JSON con:
${tasks.map((t, i) => `${i + 1}. ${t}`).join('\n')}`;

  return { prompt, schema: { type: 'object', properties }, maxTokens };
}

// Estrae il sommario dal JSON parziale per mostrarlo mentre viene generato.
function partialSummary(text) {
  const m = /"summary"\s*:\s*"((?:[^"\\]|\\.)*)/.exec(text);
  if (!m) return null;
  try { return JSON.parse(`"${m[1].replace(/\\u?[0-9a-fA-F]{0,3}$|\\$/, '')}"`); } catch { return null; }
}

/**
 * Arricchisce il report deterministico con l'analisi del modello embedded.
 */
export async function explainReport(report, { signal, onQueued, onProgress } = {}) {
  const { prompt, schema, maxTokens } = buildRequest(report);
  const started = Date.now();
  let text = '';
  let tokens = 0;
  let lastEmit = 0;

  const result = await engine.generate({
    systemPrompt: SYSTEM_PROMPT,
    prompt, schema, maxTokens, signal, onQueued,
    onToken: n => { tokens += n; },
    onText: chunk => {
      text += chunk;
      const now = Date.now();
      if (now - lastEmit > 200) {
        lastEmit = now;
        onProgress?.({ tokens, summary: partialSummary(text) });
      }
    },
  });

  const clip = (value, max) => String(value ?? '').trim().slice(0, max);
  const scenarios = {};
  for (const [id, text] of Object.entries(result.scenarios ?? {})) {
    if (report.findings.some(f => f.id === id) && clip(text, 1)) scenarios[id] = clip(text, LIMITS.scenario);
  }
  return {
    model: engine.status().model.label,
    summary: clip(result.summary, LIMITS.summary),
    scenarios,
    priorities: (Array.isArray(result.priorities) ? result.priorities : []).map(p => clip(p, LIMITS.priority)).filter(Boolean).slice(0, LIMITS.priorities),
    tokens,
    durationMs: Date.now() - started,
  };
}

export { buildRequest as _buildRequest, partialSummary as _partialSummary };
