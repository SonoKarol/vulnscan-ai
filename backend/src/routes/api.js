import { Router } from 'express';
import { config } from '../config.js';
import { engine } from '../ai/engine.js';
import { explainReport } from '../ai/analyze.js';
import { explainBuiltin } from '../ai/builtin.js';
import { runScan } from '../scanner/index.js';
import { normalizeUrl, checkTor } from '../net/http.js';

export const api = Router();

// ─── Stato ───────────────────────────────────────────────────────────────────

api.get('/status', (req, res) => {
  res.json({ version: config.version, ai: engine.status() });
});

// Separato perché la verifica passa da check.torproject.org e può impiegare secondi.
api.get('/status/tor', async (req, res) => {
  res.json({ tor: (await checkTor({ force: req.query.refresh === '1' })) ? 'online' : 'offline', proxy: config.torProxy });
});

api.post('/ai/load', (req, res) => {
  engine.load().catch(err => console.error('[AI]', err.message));
  res.status(202).json(engine.status());
});

api.post('/ai/cancel', (req, res) => {
  engine.cancel();
  res.json(engine.status());
});

// ─── Scansione (stream NDJSON) ───────────────────────────────────────────────
// Ogni riga è un evento JSON: step → report (deterministico) → ai-progress… → ai → done.
// Il report base arriva subito; l'analisi AI lo arricchisce quando è pronta.

api.post('/scan', async (req, res) => {
  const { url, ai = true } = req.body ?? {};
  let target;
  try {
    target = normalizeUrl(url);
  } catch (err) {
    return res.status(err.status || 400).json({ error: err.message });
  }

  res.status(200).set({
    'Content-Type': 'application/x-ndjson; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();

  const controller = new AbortController();
  res.on('close', () => { if (!res.writableEnded) controller.abort(); });
  const send = event => { if (!res.writableEnded && !controller.signal.aborted) res.write(JSON.stringify(event) + '\n'); };
  const step = (id, status, detail) => send({ type: 'step', id, status, detail });

  try {
    const report = await runScan(target, { step, signal: controller.signal });
    send({ type: 'report', report });

    if (ai === false) {
      step('ai', 'skipped', 'Disattivata per questa scansione');
    } else {
      step('ai', 'running');
      let result = null;
      // Il modello AI opzionale, se scaricato, ha la precedenza; altrimenti (o se
      // fallisce) l'analista integrato garantisce sempre sommario e priorità.
      if (engine.state === 'ready') {
        try {
          result = await explainReport(report, {
            signal: controller.signal,
            onQueued: position => send({ type: 'ai-queued', position }),
            onProgress: progress => send({ type: 'ai-progress', ...progress }),
          });
        } catch (err) {
          if (controller.signal.aborted) return;
          console.error('[AI ERROR] uso l\'analista integrato:', err.message);
        }
      }
      result ??= explainBuiltin(report);
      send({ type: 'ai', ai: result });
      step('ai', 'done', result.engine === 'builtin'
        ? 'analista integrato'
        : `${result.tokens} token · ${(result.durationMs / 1000).toFixed(1)} s`);
    }
    send({ type: 'done' });
  } catch (err) {
    if (!err.status) console.error('[SCAN ERROR]', err);
    send({ type: 'error', status: err.status || 500, message: err.message, details: err.details || [] });
  } finally {
    res.end();
  }
});
