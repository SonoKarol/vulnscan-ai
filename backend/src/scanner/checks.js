import { detectStacks, snippetsFor, STACK_LABELS } from './remediation.js';

// Controlli deterministici: ogni finding ha evidenza verificabile, severità
// fissa e remediation statica. L'AI li spiega, non li inventa.

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const OWASP_HEADERS = 'https://owasp.org/www-project-secure-headers/';
const MDN = h => ({ label: `MDN — ${h}`, url: `https://developer.mozilla.org/docs/Web/HTTP/Headers/${h}` });

function finding(ctx, id, severity, category, title, description, { evidence = null, references = [] } = {}) {
  ctx.findings.push({
    id, severity, category, title, description, evidence, references,
    remediation: snippetsFor(id, ctx.stacks),
  });
}

function positive(ctx, id, title, description) {
  ctx.positives.push({ id, title, description });
}

// ─── Parsing helpers ─────────────────────────────────────────────────────────

export function parseCsp(value) {
  const directives = {};
  for (const part of String(value).split(';')) {
    const [name, ...sources] = part.trim().split(/\s+/);
    if (name) directives[name.toLowerCase()] = sources.map(s => s.toLowerCase());
  }
  return directives;
}

export function parseCookie(raw) {
  const [pair, ...attrs] = String(raw).split(';');
  const name = pair.split('=')[0].trim();
  const flags = {};
  for (const a of attrs) {
    const [k, ...v] = a.trim().split('=');
    flags[k.toLowerCase()] = v.join('=').trim() || true;
  }
  return {
    name,
    secure: !!flags.secure,
    httpOnly: !!flags.httponly,
    sameSite: typeof flags.samesite === 'string' ? flags.samesite.toLowerCase() : null,
    expires: flags.expires || null,
    maxAge: flags['max-age'] ?? null,
  };
}

const SENSITIVE_COOKIE = /sess|sid|token|auth|jwt|login|remember|csrf|xsrf/i;
const list = (items, max = 5) => items.slice(0, max).join(', ') + (items.length > max ? ` e altri ${items.length - max}` : '');

// ─── Transport & TLS ─────────────────────────────────────────────────────────

function checkTransport(ctx) {
  const { isHttps, isOnion, alternate } = ctx.input;
  if (isOnion) {
    positive(ctx, 'onion-e2e', 'Servizio onion', 'Il traffico verso i servizi .onion è cifrato end-to-end dalla rete Tor anche senza HTTPS.');
    return;
  }
  if (!isHttps) {
    if (alternate?.httpsAvailable) {
      finding(ctx, 'http-no-redirect', 'medium', 'Trasporto', 'HTTPS disponibile ma non forzato',
        'Il sito risponde anche in HTTPS, ma la versione HTTP non reindirizza: chi digita l\'indirizzo senza https:// naviga in chiaro e può essere intercettato (SSL stripping).',
        { evidence: `${ctx.input.finalUrl} → ${ctx.input.status} senza redirect a HTTPS` });
    } else {
      finding(ctx, 'no-https', 'high', 'Trasporto', 'Sito servito solo in HTTP',
        'Tutto il traffico (password, cookie di sessione, form) viaggia in chiaro ed è leggibile o modificabile da chiunque sia sulla stessa rete o lungo il percorso.',
        { evidence: `HTTPS non raggiungibile su ${new URL(ctx.input.finalUrl).hostname}`, references: [{ label: 'Let\'s Encrypt — certificati gratuiti', url: 'https://letsencrypt.org/getting-started/' }] });
    }
    return;
  }
  if (alternate?.checked) {
    if (alternate.redirectsToHttps) positive(ctx, 'http-redirect', 'Redirect HTTP → HTTPS', 'Le richieste in chiaro vengono reindirizzate su HTTPS.');
    else if (alternate.httpServesContent) {
      finding(ctx, 'http-no-redirect', 'medium', 'Trasporto', 'La versione HTTP non reindirizza su HTTPS',
        'Il sito è raggiungibile anche in HTTP senza redirect: un attaccante in rete può forzare la versione in chiaro (SSL stripping).',
        { evidence: `http://${new URL(ctx.input.finalUrl).host}/ → ${alternate.httpStatus}` });
    }
  }
}

function checkTls(ctx) {
  const t = ctx.input.tls;
  if (!t) return;
  if (t.error) {
    finding(ctx, 'tls-error', 'medium', 'TLS', 'Handshake TLS non verificabile', 'Non è stato possibile completare un handshake TLS separato per analizzare il certificato.', { evidence: t.error });
    return;
  }
  const refs = [{ label: 'Mozilla SSL Configuration Generator', url: 'https://ssl-config.mozilla.org/' }];
  const err = t.authorizationError || '';
  if (t.daysLeft != null && t.daysLeft < 0) {
    finding(ctx, 'tls-expired', 'critical', 'TLS', 'Certificato TLS scaduto',
      'I browser mostrano un avviso bloccante e gli utenti abituati a "proseguire comunque" diventano vulnerabili a man-in-the-middle.',
      { evidence: `Scaduto il ${t.validTo?.slice(0, 10)} (${-t.daysLeft} giorni fa)`, references: refs });
  } else if (!t.authorized) {
    const selfSigned = /SELF_SIGNED/i.test(err);
    const mismatch = /ALTNAME|hostname/i.test(err);
    finding(ctx, 'tls-invalid', 'high', 'TLS',
      selfSigned ? 'Certificato TLS autofirmato' : mismatch ? 'Certificato TLS non valido per questo dominio' : 'Certificato TLS non attendibile',
      'Il certificato non è verificabile da una CA riconosciuta: i browser mostrano un avviso e la connessione non garantisce l\'identità del server.',
      { evidence: err || 'catena non verificata', references: refs });
  } else if (t.daysLeft != null && t.daysLeft < 14) {
    finding(ctx, 'tls-expiring', 'medium', 'TLS', 'Certificato TLS in scadenza',
      'Il certificato scade a breve: se il rinnovo automatico non funziona il sito diventerà inaccessibile o mostrerà avvisi.',
      { evidence: `Scade il ${t.validTo?.slice(0, 10)} (tra ${t.daysLeft} giorni)` });
  } else {
    positive(ctx, 'tls-valid', 'Certificato TLS valido', `Emesso da ${t.issuer || 'CA attendibile'}, valido fino al ${t.validTo?.slice(0, 10)}.`);
  }
  if (/^TLSv1(\.1)?$/.test(t.protocol || '')) {
    finding(ctx, 'tls-old-protocol', 'high', 'TLS', `Protocollo obsoleto negoziato (${t.protocol})`,
      'TLS 1.0 e 1.1 sono deprecati (RFC 8996) e soggetti ad attacchi noti; i browser moderni li rifiutano.',
      { evidence: `${t.protocol} / ${t.cipher}`, references: refs });
  } else if (t.protocol === 'TLSv1.3') {
    positive(ctx, 'tls13', 'TLS 1.3', 'Il server negozia la versione più recente del protocollo.');
  }
  if (t.keyType === 'RSA' && t.bits && t.bits < 2048) {
    finding(ctx, 'tls-weak-key', 'medium', 'TLS', `Chiave del certificato debole (${t.bits} bit)`,
      'Le chiavi RSA sotto i 2048 bit non sono più considerate sicure.', { evidence: `RSA ${t.bits} bit` });
  }
}

// ─── Security headers ────────────────────────────────────────────────────────

function checkHeaders(ctx) {
  const h = ctx.input.headers;
  const { isHttps } = ctx.input;
  const rows = ctx.headerRows;

  // HSTS
  const hsts = h['strict-transport-security'];
  if (!isHttps) {
    rows.push({ name: 'Strict-Transport-Security', value: hsts || null, status: 'na', note: 'Valido solo su HTTPS' });
  } else if (!hsts) {
    rows.push({ name: 'Strict-Transport-Security', value: null, status: 'missing', note: 'Forza HTTPS nel browser' });
    finding(ctx, 'hsts-missing', 'medium', 'Header', 'HSTS assente',
      'Senza Strict-Transport-Security il browser accetta di collegarsi in HTTP alla prima visita o dopo un link "http://": un attaccante sulla rete può fare SSL stripping.',
      { references: [MDN('Strict-Transport-Security')] });
  } else {
    const maxAge = Number(/max-age=(\d+)/i.exec(hsts)?.[1] ?? 0);
    if (maxAge < 15_552_000) {
      rows.push({ name: 'Strict-Transport-Security', value: hsts, status: 'warn', note: 'max-age troppo basso' });
      finding(ctx, 'hsts-weak', 'low', 'Header', 'HSTS con max-age breve',
        `Il max-age è ${maxAge} secondi (< 180 giorni): la protezione scade presto tra una visita e l'altra.`, { evidence: hsts, references: [MDN('Strict-Transport-Security')] });
    } else {
      rows.push({ name: 'Strict-Transport-Security', value: hsts, status: 'ok' });
      positive(ctx, 'hsts', 'HSTS configurato', `max-age di ${Math.round(maxAge / 86400)} giorni${/includesubdomains/i.test(hsts) ? ', esteso ai sottodomini' : ''}.`);
    }
  }

  // CSP
  const csp = h['content-security-policy'];
  const cspRo = h['content-security-policy-report-only'];
  const cspDirectives = csp ? parseCsp(csp) : {};
  if (!csp) {
    rows.push({ name: 'Content-Security-Policy', value: cspRo ? `(report-only) ${cspRo}` : null, status: 'missing', note: 'Mitiga XSS e injection' });
    finding(ctx, 'csp-missing', 'medium', 'Header', 'Content-Security-Policy assente',
      'Senza CSP il browser esegue qualsiasi script iniettato nella pagina: una singola XSS permette di rubare sessioni o modificare i contenuti.' +
      (cspRo ? ' È presente solo una policy report-only, che non blocca nulla.' : ''),
      { references: [MDN('Content-Security-Policy'), { label: 'Google CSP Evaluator', url: 'https://csp-evaluator.withgoogle.com/' }] });
  } else {
    const script = cspDirectives['script-src'] ?? cspDirectives['default-src'];
    const issues = [];
    if (!script) {
      issues.push('nessuna restrizione script');
      finding(ctx, 'csp-unsafe-inline', 'low', 'Header', 'CSP senza restrizioni sugli script',
        'La policy non definisce né script-src né default-src, quindi non limita gli script eseguibili.', { evidence: csp });
    } else {
      const hasNonce = script.some(s => s.startsWith("'nonce-") || s.startsWith("'sha"));
      if (script.includes("'unsafe-inline'") && !hasNonce) {
        issues.push("'unsafe-inline'");
        finding(ctx, 'csp-unsafe-inline', 'medium', 'Header', "CSP permette script inline ('unsafe-inline')",
          "Con 'unsafe-inline' gli script iniettati via XSS vengono eseguiti: la CSP perde gran parte della sua efficacia.", { evidence: csp, references: [MDN('Content-Security-Policy/script-src')] });
      }
      if (script.includes("'unsafe-eval'")) {
        issues.push("'unsafe-eval'");
        finding(ctx, 'csp-unsafe-eval', 'low', 'Header', "CSP permette eval() ('unsafe-eval')",
          'eval() e simili trasformano stringhe controllate dall\'attaccante in codice eseguibile.', { evidence: csp });
      }
      if (script.some(s => s === '*' || s === 'http:' || s === 'https:' || s === 'data:')) {
        issues.push('sorgenti jolly');
        finding(ctx, 'csp-wildcard', 'medium', 'Header', 'CSP con sorgenti script troppo ampie',
          'Sorgenti come *, https: o data: permettono di caricare script da qualsiasi dominio, aggirando la policy.', { evidence: csp });
      }
    }
    rows.push({ name: 'Content-Security-Policy', value: csp, status: issues.length ? 'warn' : 'ok', note: issues.join(', ') || undefined });
    if (!issues.length) positive(ctx, 'csp', 'Content-Security-Policy restrittiva', 'Gli script eseguibili sono limitati a sorgenti esplicite.');
  }

  // Clickjacking
  const xfo = h['x-frame-options'];
  const frameAncestors = cspDirectives['frame-ancestors'];
  if (frameAncestors || /^(deny|sameorigin)$/i.test(String(xfo || '').trim())) {
    rows.push({ name: 'X-Frame-Options', value: xfo || null, status: 'ok', note: frameAncestors ? 'coperto da CSP frame-ancestors' : undefined });
    positive(ctx, 'framing', 'Protezione clickjacking', frameAncestors ? 'CSP frame-ancestors limita chi può incorniciare il sito.' : `X-Frame-Options: ${xfo}.`);
  } else {
    rows.push({ name: 'X-Frame-Options', value: xfo || null, status: xfo ? 'warn' : 'missing', note: 'Previene clickjacking' });
    finding(ctx, 'clickjacking', 'medium', 'Header', 'Protezione da clickjacking assente',
      'La pagina può essere caricata in un iframe su un sito malevolo che, con overlay trasparenti, induce l\'utente a cliccare azioni sensibili (es. conferme, cambi impostazioni).',
      { evidence: xfo ? `X-Frame-Options: ${xfo} (valore non supportato)` : null, references: [MDN('X-Frame-Options'), { label: 'OWASP — Clickjacking', url: 'https://owasp.org/www-community/attacks/Clickjacking' }] });
  }

  // X-Content-Type-Options
  const xcto = h['x-content-type-options'];
  if (String(xcto || '').toLowerCase().trim() === 'nosniff') {
    rows.push({ name: 'X-Content-Type-Options', value: xcto, status: 'ok' });
  } else {
    rows.push({ name: 'X-Content-Type-Options', value: xcto || null, status: 'missing', note: 'Previene MIME sniffing' });
    finding(ctx, 'nosniff-missing', 'low', 'Header', 'X-Content-Type-Options mancante',
      'Il browser può "indovinare" il tipo di un file: un upload di testo può essere interpretato come script o HTML.', { references: [MDN('X-Content-Type-Options')] });
  }

  // Referrer-Policy
  const rp = String(h['referrer-policy'] || '').toLowerCase();
  if (!rp) {
    rows.push({ name: 'Referrer-Policy', value: null, status: 'missing', note: 'Limita i dati nel Referer' });
    finding(ctx, 'referrer-policy-missing', 'low', 'Header', 'Referrer-Policy non impostata',
      'Gli URL completi (che possono contenere token o dati personali) possono finire nell\'header Referer verso siti terzi.', { references: [MDN('Referrer-Policy')] });
  } else if (/unsafe-url|no-referrer-when-downgrade/.test(rp)) {
    rows.push({ name: 'Referrer-Policy', value: rp, status: 'warn', note: 'Policy permissiva' });
    finding(ctx, 'referrer-policy-weak', 'low', 'Header', 'Referrer-Policy permissiva',
      'La policy invia l\'URL completo anche a domini esterni.', { evidence: rp, references: [MDN('Referrer-Policy')] });
  } else {
    rows.push({ name: 'Referrer-Policy', value: rp, status: 'ok' });
  }

  // Permissions-Policy
  const pp = h['permissions-policy'];
  rows.push({ name: 'Permissions-Policy', value: pp || null, status: pp ? 'ok' : 'missing', note: pp ? undefined : 'Limita API del browser' });
  if (!pp) {
    finding(ctx, 'permissions-policy-missing', 'info', 'Header', 'Permissions-Policy non impostata',
      'Non vengono limitate le API sensibili del browser (fotocamera, microfono, geolocalizzazione) per la pagina e gli iframe incorporati.', { references: [MDN('Permissions-Policy')] });
  }

  // X-XSS-Protection (deprecato: il valore consigliato oggi è 0 o assente)
  const xxss = h['x-xss-protection'];
  if (xxss && !/^\s*0/.test(xxss)) {
    rows.push({ name: 'X-XSS-Protection', value: xxss, status: 'warn', note: 'Header legacy' });
    finding(ctx, 'xxss-legacy', 'info', 'Header', 'X-XSS-Protection legacy attivo',
      'Il filtro XSS dei browser è stato rimosso e in passato ha introdotto vulnerabilità di information leak: OWASP consiglia di impostarlo a 0 e affidarsi alla CSP.', { evidence: xxss, references: [{ label: 'OWASP Secure Headers', url: OWASP_HEADERS }] });
  } else {
    rows.push({ name: 'X-XSS-Protection', value: xxss || null, status: 'ok', note: xxss ? undefined : 'Deprecato: assente è corretto' });
  }
}

// ─── Information disclosure ──────────────────────────────────────────────────

function checkDisclosure(ctx) {
  const h = ctx.input.headers;
  if (h.server && /\d/.test(h.server)) {
    finding(ctx, 'server-version', 'low', 'Information disclosure', 'Versione del server esposta',
      'Conoscere la versione esatta permette a un attaccante di cercare CVE note per quella release senza fare rumore.', { evidence: `Server: ${h.server}` });
  }
  if (h['x-powered-by']) {
    finding(ctx, 'powered-by', 'low', 'Information disclosure', 'Tecnologia esposta da X-Powered-By',
      'L\'header rivela framework e spesso versione del backend, facilitando la scelta degli exploit.', { evidence: `X-Powered-By: ${h['x-powered-by']}` });
  }
  const asp = h['x-aspnet-version'] || h['x-aspnetmvc-version'];
  if (asp) {
    finding(ctx, 'aspnet-version', 'low', 'Information disclosure', 'Versione ASP.NET esposta',
      'La versione del runtime è visibile in ogni risposta.', { evidence: `X-AspNet-Version: ${asp}` });
  }
  const generator = ctx.tech.generator;
  if (generator && /\d/.test(generator)) {
    finding(ctx, 'generator-version', 'low', 'Information disclosure', 'Versione del CMS esposta',
      'Il tag <meta name="generator"> rivela CMS e versione: i bot automatizzati lo usano per trovare installazioni vulnerabili.', { evidence: generator });
  }
}

// ─── Cookies ─────────────────────────────────────────────────────────────────

function checkCookies(ctx) {
  const raw = ctx.input.headers['set-cookie'];
  const cookies = (Array.isArray(raw) ? raw : raw ? [raw] : []).map(parseCookie);
  ctx.cookies = cookies;
  if (!cookies.length) return;
  const { isHttps } = ctx.input;
  const ref = [{ label: 'MDN — Cookie sicuri', url: 'https://developer.mozilla.org/docs/Web/HTTP/Cookies#restrict_access_to_cookies' }];

  const insecure = cookies.filter(c => !c.secure);
  if (isHttps && insecure.length) {
    finding(ctx, 'cookie-insecure', 'medium', 'Cookie', 'Cookie senza flag Secure',
      'Questi cookie verrebbero inviati anche su connessioni HTTP in chiaro, dove possono essere intercettati.',
      { evidence: list(insecure.map(c => c.name)), references: ref });
  }
  const noHttpOnly = cookies.filter(c => !c.httpOnly);
  if (noHttpOnly.length) {
    const sensitive = noHttpOnly.some(c => SENSITIVE_COOKIE.test(c.name));
    finding(ctx, 'cookie-no-httponly', sensitive ? 'medium' : 'low', 'Cookie', 'Cookie accessibili da JavaScript (manca HttpOnly)',
      'In caso di XSS lo script dell\'attaccante può leggere questi cookie' + (sensitive ? ', inclusi quelli che sembrano di sessione/autenticazione.' : '.'),
      { evidence: list(noHttpOnly.map(c => c.name)), references: ref });
  }
  const noSameSite = cookies.filter(c => !c.sameSite || (c.sameSite === 'none' && !c.secure));
  if (noSameSite.length) {
    finding(ctx, 'cookie-no-samesite', 'low', 'Cookie', 'Cookie senza SameSite esplicito',
      'Senza SameSite il comportamento dipende dal browser e la protezione da CSRF non è garantita.',
      { evidence: list(noSameSite.map(c => c.name)), references: ref });
  }
  if (!insecure.length && !noHttpOnly.length && !noSameSite.length) {
    positive(ctx, 'cookies', 'Cookie configurati correttamente', `${cookies.length} cookie con Secure, HttpOnly e SameSite.`);
  }
}

// ─── CORS ────────────────────────────────────────────────────────────────────

function checkCors(ctx) {
  const h = ctx.input.headers;
  const acao = h['access-control-allow-origin'];
  if (!acao) return;
  const creds = String(h['access-control-allow-credentials'] || '').toLowerCase() === 'true';
  const ref = [{ label: 'PortSwigger — CORS', url: 'https://portswigger.net/web-security/cors' }];
  if (acao === ctx.input.probeOrigin || acao === 'null') {
    finding(ctx, creds ? 'cors-reflect-credentials' : 'cors-reflect', creds ? 'high' : 'medium', 'CORS',
      creds ? 'CORS riflette qualsiasi origine con credenziali' : 'CORS riflette qualsiasi origine',
      creds
        ? 'Il server accetta come attendibile qualunque sito e consente l\'invio dei cookie: una pagina malevola può leggere le risposte autenticate dell\'utente.'
        : 'Il server autorizza qualunque origine a leggere le risposte: i dati non autenticati sono leggibili da qualsiasi sito.',
      { evidence: `Origin: ${ctx.input.probeOrigin} → Access-Control-Allow-Origin: ${acao}${creds ? ', Allow-Credentials: true' : ''}`, references: ref });
  } else if (acao === '*') {
    finding(ctx, 'cors-wildcard', 'info', 'CORS', 'CORS aperto a tutte le origini (*)',
      'Accettabile per API pubbliche e asset statici; da evitare se la risposta contiene dati riservati.', { evidence: 'Access-Control-Allow-Origin: *', references: ref });
  }
}

// ─── File sensibili ──────────────────────────────────────────────────────────

function checkExposedFiles(ctx) {
  const files = ctx.input.files || {};
  if (files.git) {
    finding(ctx, 'git-exposed', 'critical', 'File esposti', 'Repository .git accessibile pubblicamente',
      'Dalla cartella .git si può ricostruire l\'intero codice sorgente, inclusa la cronologia: spesso contiene password, chiavi API e configurazioni.',
      { evidence: `GET /.git/HEAD → 200 (${files.git})`, references: [{ label: 'OWASP WSTG — Review old/backup files', url: 'https://owasp.org/www-project-web-security-testing-guide/' }] });
  }
  if (files.env) {
    finding(ctx, 'env-exposed', 'critical', 'File esposti', 'File .env accessibile pubblicamente',
      'Il file .env contiene tipicamente credenziali del database, chiavi API e segreti applicativi. Considera tutte le credenziali compromesse e ruotale.',
      { evidence: `GET /.env → 200 (${files.env})` });
  }
  if (files.securityTxt) {
    positive(ctx, 'security-txt', 'security.txt presente', 'È indicato un contatto per segnalare vulnerabilità (RFC 9116).');
  } else if (files.securityTxt === false) {
    finding(ctx, 'security-txt-missing', 'info', 'Best practice', 'security.txt assente',
      'Un file /.well-known/security.txt (RFC 9116) dice ai ricercatori come segnalarti una vulnerabilità invece di divulgarla.',
      { references: [{ label: 'securitytxt.org', url: 'https://securitytxt.org/' }] });
  }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

export function extractGenerator(body) {
  const tag = /<meta\b[^>]*\bname\s*=\s*["']generator["'][^>]*>/i.exec(body || '')?.[0];
  return tag ? /content\s*=\s*["']([^"']{1,120})["']/i.exec(tag)?.[1] ?? null : null;
}

/**
 * @param input { finalUrl, isHttps, isOnion, status, headers, body, tls, alternate, files, probeOrigin }
 */
export function analyze(input) {
  const headers = input.headers || {};
  const ctx = {
    input: { ...input, headers },
    stacks: detectStacks(headers),
    findings: [], positives: [], headerRows: [], cookies: [],
    tech: {
      server: headers.server || null,
      poweredBy: headers['x-powered-by'] || null,
      generator: extractGenerator(input.body),
      contentType: headers['content-type'] || null,
    },
  };
  checkTransport(ctx);
  checkTls(ctx);
  checkHeaders(ctx);
  checkDisclosure(ctx);
  checkCookies(ctx);
  checkCors(ctx);
  checkExposedFiles(ctx);

  ctx.findings.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  return {
    findings: ctx.findings,
    positives: ctx.positives,
    headers: ctx.headerRows,
    cookies: ctx.cookies,
    tech: { ...ctx.tech, stacks: ctx.stacks.map(s => STACK_LABELS[s]) },
  };
}
