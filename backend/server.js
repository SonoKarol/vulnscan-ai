import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import { config } from './src/config.js';
import { api } from './src/routes/api.js';
import { engine } from './src/ai/engine.js';

const app = express();
const dist = path.resolve(config.root, '../frontend/dist');

app.disable('x-powered-by');

// Uno scanner di sicurezza dovrebbe superare i propri controlli.
app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
  });
  next();
});

app.use(express.json({ limit: '16kb' }));
app.use('/api', api);
app.get('/api/health', (req, res) => res.json({ status: 'ok', version: config.version }));
app.use('/api', (req, res) => res.status(404).json({ error: 'Endpoint non trovato' }));

// In produzione il backend serve anche il frontend compilato (npm run build).
if (fs.existsSync(dist)) {
  app.use(express.static(dist, { index: false, maxAge: '1h' }));
  app.get('/{*path}', (req, res) => res.sendFile(path.join(dist, 'index.html')));
}

app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON non valido' });
  console.error('[SERVER ERROR]', err);
  res.status(500).json({ error: 'Errore interno' });
});

const server = app.listen(config.port, config.host, () => {
  const { model, enabled } = config.ai;
  console.log(`🛡️  VulnScan AI ${config.version} → http://${config.host === '0.0.0.0' ? 'localhost' : config.host}:${config.port}`);
  console.log(enabled ? `🧠 AI embedded: ${model.label} (${model.uri})` : '🧠 AI disabilitata (AI_ENABLED=false)');
  engine.init().catch(err => console.error('[AI]', err.message));
});

async function shutdown() {
  server.close();
  await engine.dispose().catch(() => {});
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
