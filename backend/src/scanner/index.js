import { randomUUID } from 'node:crypto';
import {
  ScanError, normalizeUrl, isOnion, assertPublicTarget, fetchWithRedirects, request, probeTls, checkTor,
} from '../net/http.js';
import { analyze } from './checks.js';
import { score } from './score.js';

// Origine fittizia usata per verificare se il server riflette l'header Origin (CORS).
const PROBE_ORIGIN = 'https://vulnscan-cors-probe.invalid';

async function quiet(promise) {
  try { return await promise; } catch { return null; }
}

// Su HTTPS verifica che la versione HTTP reindirizzi; su HTTP verifica se HTTPS esiste.
async function probeAlternate(finalUrl, signal) {
  const url = new URL(finalUrl);
  const alt = new URL(url.origin);
  alt.protocol = url.protocol === 'https:' ? 'http:' : 'https:';
  const res = await quiet(request(alt.href, { timeout: 6000, maxBytes: 16_000, signal }));
  if (url.protocol === 'https:') {
    if (!res) return { checked: true, redirectsToHttps: false, httpServesContent: false };
    const location = res.headers.location ? new URL(res.headers.location, alt).protocol : null;
    return {
      checked: true,
      httpStatus: res.status,
      redirectsToHttps: res.status >= 300 && res.status < 400 && location === 'https:',
      httpServesContent: res.status < 300,
    };
  }
  return { checked: true, httpsAvailable: !!res && res.status < 500 };
}

async function probeFiles(finalUrl, signal) {
  const origin = new URL(finalUrl).origin;
  const get = path => quiet(request(origin + path, { timeout: 6000, maxBytes: 8_000, signal }));
  const [git, env, sec] = await Promise.all([get('/.git/HEAD'), get('/.env'), get('/.well-known/security.txt')]);
  const isHtml = r => /<html|<!doctype/i.test(r.body.slice(0, 500)) || /html/i.test(r.headers['content-type'] || '');

  const files = {};
  if (git?.status === 200 && /^(ref: refs\/|[0-9a-f]{40}\s*$)/.test(git.body.trim())) {
    files.git = git.body.trim().slice(0, 60);
  }
  // Non riportiamo mai il contenuto del .env: solo il fatto che è leggibile.
  if (env?.status === 200 && !isHtml(env) && /^\s*[A-Z][A-Z0-9_]*\s*=/m.test(env.body)) {
    const vars = (env.body.match(/^\s*[A-Z][A-Z0-9_]*\s*=/gm) || []).length;
    files.env = `${vars} variabili d'ambiente leggibili`;
  }
  files.securityTxt = !!(sec?.status === 200 && !isHtml(sec) && /^contact:/im.test(sec.body));
  return files;
}

/**
 * Esegue la parte deterministica della scansione.
 * @param {string} rawUrl
 * @param {{ step: (id: string, status: string, detail?: string) => void, signal?: AbortSignal }} hooks
 */
export async function runScan(rawUrl, { step = () => {}, signal } = {}) {
  const target = normalizeUrl(rawUrl);
  const onion = isOnion(target);
  const started = Date.now();

  step('resolve', 'running');
  if (onion) {
    if (!(await checkTor({ force: true }))) {
      throw new ScanError(503, 'Tor non raggiungibile', ['Avvia Tor Browser o il servizio tor prima di scansionare siti .onion']);
    }
  } else {
    await assertPublicTarget(target);
  }
  step('resolve', 'done', onion ? 'Instradamento via Tor' : new URL(target).hostname);

  step('fetch', 'running');
  let main;
  try {
    main = await fetchWithRedirects(target, { headers: { Origin: PROBE_ORIGIN }, signal });
  } catch (err) {
    if (err instanceof ScanError) throw err;
    throw new ScanError(422,
      onion ? 'Sito .onion non raggiungibile — potrebbe essere offline o l\'indirizzo non è corretto' : 'Sito non raggiungibile',
      [err.message || String(err)]);
  }
  const responseTime = Date.now() - started;
  step('fetch', 'done', `HTTP ${main.status} · ${responseTime} ms`);

  const finalUrl = main.url;
  const isHttps = new URL(finalUrl).protocol === 'https:';

  step('tls', 'running');
  const tlsPromise = isHttps && !onion ? probeTls(finalUrl) : Promise.resolve(null);
  const [tls, alternate, files] = await Promise.all([
    tlsPromise,
    onion ? null : quiet(probeAlternate(finalUrl, signal)),
    quiet(probeFiles(finalUrl, signal)),
  ]);
  step('tls', tls ? 'done' : 'skipped', tls ? (tls.error ? 'non verificabile' : `${tls.protocol} · ${tls.issuer ?? ''}`) : isHttps ? 'servizio onion' : 'sito non HTTPS');

  step('analyze', 'running');
  const analysis = analyze({
    finalUrl, isHttps, isOnion: onion,
    status: main.status, headers: main.headers, body: main.body,
    tls, alternate, files, probeOrigin: PROBE_ORIGIN,
  });
  const scoring = score(analysis.findings);
  step('analyze', 'done', `${analysis.findings.length} problemi rilevati`);

  return {
    id: randomUUID(),
    scannedAt: new Date().toISOString(),
    target,
    finalUrl,
    isOnion: onion,
    isHttps,
    statusCode: main.status,
    responseTime,
    redirects: main.chain,
    tls,
    ...analysis,
    ...scoring,
    ai: null,
  };
}
