import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, parseCsp, parseCookie, extractGenerator } from '../src/scanner/checks.js';
import { score } from '../src/scanner/score.js';
import { detectStacks, snippetsFor } from '../src/scanner/remediation.js';
import { isPrivateIp, normalizeUrl } from '../src/net/http.js';
import { _buildRequest, _partialSummary } from '../src/ai/analyze.js';

const SECURE_HEADERS = {
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
  'content-security-policy': "default-src 'self'; script-src 'self' 'nonce-abc'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=()',
  'set-cookie': ['sid=1; Secure; HttpOnly; SameSite=Lax'],
};

const base = overrides => ({
  finalUrl: 'https://esempio.it/', isHttps: true, isOnion: false, status: 200,
  headers: {}, body: '', probeOrigin: 'https://probe.invalid',
  tls: { authorized: true, protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384', issuer: "Let's Encrypt", validTo: '2099-01-01T00:00:00.000Z', daysLeft: 9000, bits: 256, keyType: 'EC' },
  alternate: { checked: true, redirectsToHttps: true },
  files: { securityTxt: true },
  ...overrides,
});

const ids = result => result.findings.map(f => f.id);

test('sito ben configurato: nessun finding e voto A', () => {
  const result = analyze(base({ headers: SECURE_HEADERS }));
  assert.deepEqual(ids(result), []);
  const s = score(result.findings);
  assert.equal(s.score, 100);
  assert.equal(s.grade, 'A');
  assert.equal(s.riskLevel, 'none');
  assert.ok(result.positives.some(p => p.id === 'hsts'));
});

test('header mancanti producono i finding attesi', () => {
  const result = analyze(base({ headers: {} }));
  for (const id of ['hsts-missing', 'csp-missing', 'clickjacking', 'nosniff-missing', 'referrer-policy-missing', 'permissions-policy-missing']) {
    assert.ok(ids(result).includes(id), `manca ${id}`);
  }
  assert.ok(score(result.findings).score < 75);
});

test('CSP con unsafe-inline senza nonce è segnalata, con nonce no', () => {
  const weak = analyze(base({ headers: { ...SECURE_HEADERS, 'content-security-policy': "script-src 'self' 'unsafe-inline'" } }));
  assert.ok(ids(weak).includes('csp-unsafe-inline'));
  const nonce = analyze(base({ headers: { ...SECURE_HEADERS, 'content-security-policy': "script-src 'self' 'unsafe-inline' 'nonce-x'; frame-ancestors 'self'" } }));
  assert.ok(!ids(nonce).includes('csp-unsafe-inline'));
});

test('HTTP senza HTTPS è high, HSTS non applicabile', () => {
  const result = analyze(base({ finalUrl: 'http://esempio.it/', isHttps: false, tls: null, alternate: { checked: true, httpsAvailable: false } }));
  assert.ok(ids(result).includes('no-https'));
  assert.ok(!ids(result).includes('hsts-missing'));
  assert.equal(result.headers.find(h => h.name === 'Strict-Transport-Security').status, 'na');
});

test('onion su HTTP non viene penalizzato per l\'assenza di HTTPS', () => {
  const result = analyze(base({ finalUrl: 'http://abc.onion/', isHttps: false, isOnion: true, tls: null, alternate: null }));
  assert.ok(!ids(result).includes('no-https'));
  assert.ok(result.positives.some(p => p.id === 'onion-e2e'));
});

test('chiave RSA corta segnalata, EC a 256 bit no', () => {
  const tls = base().tls;
  assert.ok(ids(analyze(base({ headers: SECURE_HEADERS, tls: { ...tls, keyType: 'RSA', bits: 1024 } }))).includes('tls-weak-key'));
  assert.ok(!ids(analyze(base({ headers: SECURE_HEADERS, tls: { ...tls, keyType: 'RSA', bits: 2048 } }))).includes('tls-weak-key'));
});

test('certificato scaduto è critico', () => {
  const result = analyze(base({ headers: SECURE_HEADERS, tls: { authorized: false, authorizationError: 'CERT_HAS_EXPIRED', protocol: 'TLSv1.2', daysLeft: -3, validTo: '2020-01-01T00:00:00.000Z' } }));
  assert.equal(result.findings[0].id, 'tls-expired');
  assert.equal(result.findings[0].severity, 'critical');
});

test('cookie di sessione senza flag e CORS riflesso con credenziali', () => {
  const result = analyze(base({
    headers: {
      ...SECURE_HEADERS,
      'set-cookie': ['sessionid=abc; Path=/'],
      'access-control-allow-origin': 'https://probe.invalid',
      'access-control-allow-credentials': 'true',
    },
  }));
  const byId = Object.fromEntries(result.findings.map(f => [f.id, f]));
  assert.equal(byId['cookie-insecure'].severity, 'medium');
  assert.equal(byId['cookie-no-httponly'].severity, 'medium');
  assert.equal(byId['cors-reflect-credentials'].severity, 'high');
});

test('file esposti: il contenuto del .env non finisce nel report', () => {
  const result = analyze(base({ headers: SECURE_HEADERS, files: { env: '3 variabili d\'ambiente leggibili', securityTxt: false } }));
  const env = result.findings.find(f => f.id === 'env-exposed');
  assert.equal(env.severity, 'critical');
  assert.ok(!/PASSWORD|=/.test(env.evidence));
});

test('X-XSS-Protection: assente è corretto, 1; mode=block è legacy', () => {
  assert.ok(!ids(analyze(base({ headers: SECURE_HEADERS }))).includes('xxss-legacy'));
  assert.ok(ids(analyze(base({ headers: { ...SECURE_HEADERS, 'x-xss-protection': '1; mode=block' } }))).includes('xxss-legacy'));
});

test('findings ordinati per gravità', () => {
  const result = analyze(base({ headers: { server: 'nginx/1.18.0' }, files: { git: 'ref: refs/heads/main' } }));
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const sev = result.findings.map(f => order.indexOf(f.severity));
  assert.deepEqual(sev, [...sev].sort((a, b) => a - b));
  assert.equal(result.findings[0].id, 'git-exposed');
});

test('parser e utility', () => {
  assert.deepEqual(parseCsp("default-src 'self'; script-src a b")['script-src'], ['a', 'b']);
  assert.deepEqual(parseCookie('id=1; Secure; HttpOnly; SameSite=Strict'), { name: 'id', secure: true, httpOnly: true, sameSite: 'strict', expires: null, maxAge: null });
  assert.equal(extractGenerator('<meta content="WordPress 6.4" name="generator">'), 'WordPress 6.4');
  assert.deepEqual(detectStacks({ server: 'nginx', 'x-powered-by': 'Express' }), ['express', 'nginx']);
  assert.equal(snippetsFor('hsts-missing', ['nginx'])[0].code, 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;');
  assert.equal(snippetsFor('hsts-missing', []).length, 3);
});

test('guardia SSRF', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.20.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', 'fd00::1', 'fe80::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '64:ff9b::a00:1']) {
    assert.ok(isPrivateIp(ip), ip);
  }
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700::1111', '64:ff9b::808:808']) {
    assert.ok(!isPrivateIp(ip), ip);
  }
});

test('normalizzazione URL', () => {
  assert.equal(normalizeUrl('esempio.it'), 'http://esempio.it/');
  assert.equal(normalizeUrl(' https://esempio.it/a#x '), 'https://esempio.it/a');
  assert.throws(() => normalizeUrl('ftp://x'), /solo URL/);
  assert.throws(() => normalizeUrl(''), /obbligatorio/);
});

test('prompt AI: schema con uno scenario per finding e budget di token sufficiente', () => {
  const result = analyze(base({ headers: {} }));
  const report = { ...result, ...score(result.findings), finalUrl: 'https://esempio.it/', isHttps: true, statusCode: 200, responseTime: 50, tls: null };
  const { schema, prompt, maxTokens } = _buildRequest(report);
  const focus = result.findings.filter(f => f.severity !== 'info');
  assert.deepEqual(Object.keys(schema.properties.scenarios.properties), focus.map(f => f.id));
  assert.ok(prompt.includes('[csp-missing]'));
  const maxChars = schema.properties.summary.maxLength
    + focus.length * schema.properties.scenarios.properties[focus[0].id].maxLength
    + schema.properties.priorities.maxItems * schema.properties.priorities.items.maxLength;
  assert.ok(maxTokens > maxChars);
});

test('sommario parziale durante lo streaming', () => {
  assert.equal(_partialSummary('{"summary": "Il sito \\"esempio\\" ha'), 'Il sito "esempio" ha');
  assert.equal(_partialSummary('{"summary": "Riga\\'), 'Riga');
  assert.equal(_partialSummary('{"summ'), null);
});
