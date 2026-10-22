import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../src/scanner/checks.js';
import { score } from '../src/scanner/score.js';
import { explainBuiltin, _SCENARIOS, _ACTIONS } from '../src/ai/builtin.js';

// Tutti gli id che checks.js può produrre.
const ALL_IDS = [
  'aspnet-version', 'clickjacking', 'cookie-insecure', 'cookie-no-httponly', 'cookie-no-samesite',
  'cors-reflect', 'cors-reflect-credentials', 'cors-wildcard', 'csp-missing', 'csp-unsafe-eval',
  'csp-unsafe-inline', 'csp-wildcard', 'env-exposed', 'generator-version', 'git-exposed',
  'hsts-missing', 'hsts-weak', 'http-no-redirect', 'no-https', 'nosniff-missing',
  'permissions-policy-missing', 'powered-by', 'referrer-policy-missing', 'referrer-policy-weak',
  'security-txt-missing', 'server-version', 'tls-error', 'tls-expired', 'tls-expiring',
  'tls-invalid', 'tls-old-protocol', 'tls-weak-key', 'xxss-legacy',
];

function makeReport(input) {
  const result = analyze({
    finalUrl: 'https://esempio.it/', isHttps: true, isOnion: false, status: 200,
    headers: {}, body: '', probeOrigin: 'https://probe.invalid',
    tls: { authorized: true, protocol: 'TLSv1.3', issuer: 'CA', validTo: '2099-01-01T00:00:00.000Z', daysLeft: 9000, keyType: 'EC', bits: 256 },
    alternate: { checked: true, redirectsToHttps: true },
    files: { securityTxt: true },
    ...input,
  });
  return { ...result, ...score(result.findings), finalUrl: input.finalUrl ?? 'https://esempio.it/', isOnion: !!input.isOnion, isHttps: input.isHttps ?? true };
}

const BAD = makeReport({
  headers: {
    server: 'nginx/1.18.0',
    'x-powered-by': 'Express',
    'set-cookie': ['sessionid=abc; Path=/', 'pref=1'],
    'access-control-allow-origin': 'https://probe.invalid',
    'access-control-allow-credentials': 'true',
  },
  files: { env: '4 variabili d\'ambiente leggibili', git: 'ref: refs/heads/main', securityTxt: false },
});

test('ogni finding possibile ha uno scenario e un\'azione', () => {
  assert.deepEqual(Object.keys(_SCENARIOS).sort(), [...ALL_IDS].sort());
  const covered = new Set(_ACTIONS.flatMap(a => a.ids));
  for (const id of ALL_IDS) assert.ok(covered.has(id), `nessuna priorità per ${id}`);
});

test('stessa forma dell\'analisi LLM, deterministica', () => {
  const a = explainBuiltin(BAD);
  const b = explainBuiltin(BAD);
  assert.equal(a.engine, 'builtin');
  assert.equal(a.model, 'Analista integrato');
  assert.equal(typeof a.summary, 'string');
  assert.ok(a.summary.length > 40);
  assert.deepEqual({ ...a, durationMs: 0 }, { ...b, durationMs: 0 });
  assert.ok(a.priorities.length >= 1 && a.priorities.length <= 5);
});

test('scenario per ogni finding non informativo, contestualizzato', () => {
  const { scenarios } = explainBuiltin(BAD);
  for (const f of BAD.findings.filter(f => f.severity !== 'info')) {
    assert.ok(scenarios[f.id], `manca lo scenario per ${f.id}`);
  }
  assert.ok(!scenarios['permissions-policy-missing']);
  assert.match(scenarios['cookie-no-httponly'], /sessionid/);
  assert.match(scenarios['server-version'], /nginx\/1\.18\.0/);
  assert.match(scenarios['csp-missing'], /esempio\.it/);
});

test('priorità: prima i file esposti, poi per gravità, con lo stack rilevato', () => {
  const { priorities } = explainBuiltin(BAD);
  assert.match(priorities[0], /\/\.git e \/\.env/);
  assert.match(priorities[0], /ruotale/);
  assert.ok(priorities.some(p => /CORS/.test(p)));
  assert.ok(priorities.some(p => /nginx/.test(p)));
});

test('il contenuto del .env non compare mai nei testi', () => {
  const out = JSON.stringify(explainBuiltin(BAD));
  assert.ok(!/DB_PASSWORD|API_KEY/.test(out));
});

test('sito pulito: sommario positivo, nessun problema inventato', () => {
  const clean = makeReport({
    headers: {
      'strict-transport-security': 'max-age=63072000; includeSubDomains',
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'permissions-policy': 'camera=()',
    },
  });
  const out = explainBuiltin(clean);
  assert.match(out.summary, /supera tutti i controlli/);
  // le sigle restano maiuscole nel testo
  const tls13 = explainBuiltin(makeReport({ alternate: null, headers: { 'strict-transport-security': 'max-age=63072000' } }));
  assert.match(tls13.summary, /TLS 1\.3/);
  assert.deepEqual(out.scenarios, {});
  assert.deepEqual(out.priorities, []);
});

test('sito HTTP: HTTPS è tra le prime priorità', () => {
  const http = makeReport({ finalUrl: 'http://esempio.it/', isHttps: false, tls: null, alternate: { checked: true, httpsAvailable: false } });
  const out = explainBuiltin(http);
  assert.match(out.priorities[0], /Attiva HTTPS/);
  assert.match(out.summary, /voto/);
});

test('onion: avvisa sul rischio di deanonimizzazione', () => {
  const onion = makeReport({ finalUrl: 'http://abc.onion/', isHttps: false, isOnion: true, tls: null, alternate: null, headers: { server: 'Apache/2.4.1' } });
  const out = explainBuiltin(onion);
  assert.match(out.scenarios['server-version'], /deanonimizzarlo/);
  assert.match(out.summary, /\.onion/);
});
