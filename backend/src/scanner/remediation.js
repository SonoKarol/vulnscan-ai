// Snippet di correzione per i finding deterministici, per stack. Sono statici
// (e verificati) di proposito: il modello AI aggiunge contesto e priorità, ma la
// configurazione da copiare non deve dipendere da un LLM.

// Restituisce gli stack rilevati, dal più specifico (applicazione) al più
// esterno (web server / CDN): es. Express dietro nginx → ['express', 'nginx'].
export function detectStacks(headers) {
  const server = String(headers.server || '').toLowerCase();
  const powered = String(headers['x-powered-by'] || '').toLowerCase();
  const stacks = [];
  if (powered.includes('express')) stacks.push('express');
  if (powered.includes('next.js')) stacks.push('nextjs');
  if (powered.includes('asp.net') || server.includes('microsoft-iis')) stacks.push('iis');
  if (server.includes('nginx') || server.includes('openresty')) stacks.push('nginx');
  if (server.includes('apache') || (powered.includes('php') && !server)) stacks.push('apache');
  if (server.includes('caddy')) stacks.push('caddy');
  if (server.includes('cloudflare')) stacks.push('cloudflare');
  return stacks;
}

export const STACK_LABELS = {
  nginx: 'nginx', apache: 'Apache', express: 'Node / Express', nextjs: 'Next.js',
  iis: 'IIS (web.config)', caddy: 'Caddy', cloudflare: 'Cloudflare',
};

const header = (name, value) => ({
  nginx:   `add_header ${name} "${value}" always;`,
  apache:  `Header always set ${name} "${value}"`,
  express: `app.use((req, res, next) => {\n  res.setHeader('${name}', "${value}");\n  next();\n});\n// oppure: npm i helmet → app.use(helmet())`,
  nextjs:  `// next.config.js\nheaders: async () => [{\n  source: '/(.*)',\n  headers: [{ key: '${name}', value: "${value}" }],\n}]`,
  iis:     `<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n      <add name="${name}" value="${value.replace(/"/g, '&quot;')}" />\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>`,
  caddy:   `header ${name} "${value}"`,
  cloudflare: `Rules → Transform Rules → Modify Response Header\nSet static: ${name} = ${value}`,
});

const SNIPPETS = {
  'hsts-missing': header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains'),
  'hsts-weak':    header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains'),
  'csp-missing':  header('Content-Security-Policy', "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"),
  'csp-unsafe-inline': header('Content-Security-Policy', "script-src 'self' 'nonce-{RANDOM}'; object-src 'none'; base-uri 'self'"),
  'csp-unsafe-eval':   header('Content-Security-Policy', "script-src 'self'; object-src 'none'; base-uri 'self'"),
  'csp-wildcard':      header('Content-Security-Policy', "script-src 'self' https://cdn.esempio.it; object-src 'none'"),
  'clickjacking': header('Content-Security-Policy', "frame-ancestors 'self'"),
  'nosniff-missing': header('X-Content-Type-Options', 'nosniff'),
  'referrer-policy-missing': header('Referrer-Policy', 'strict-origin-when-cross-origin'),
  'referrer-policy-weak':    header('Referrer-Policy', 'strict-origin-when-cross-origin'),
  'permissions-policy-missing': header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()'),
  'xxss-legacy': header('X-XSS-Protection', '0'),
  'server-version': {
    nginx:  'server_tokens off;',
    apache: 'ServerTokens Prod\nServerSignature Off',
    iis:    '<system.webServer>\n  <security>\n    <requestFiltering removeServerHeader="true" />\n  </security>\n</system.webServer>',
    caddy:  'header -Server',
  },
  'powered-by': {
    express: "app.disable('x-powered-by');",
    nextjs:  '// next.config.js\npoweredByHeader: false',
    apache:  '# php.ini\nexpose_php = Off\n\n# oppure\nHeader always unset X-Powered-By',
    nginx:   'proxy_hide_header X-Powered-By;\nfastcgi_hide_header X-Powered-By;',
    iis:     '<httpProtocol>\n  <customHeaders>\n    <remove name="X-Powered-By" />\n  </customHeaders>\n</httpProtocol>',
  },
  'aspnet-version': {
    iis: '<system.web>\n  <httpRuntime enableVersionHeader="false" />\n</system.web>\n\n// Global.asax: MvcHandler.DisableMvcResponseHeader = true;',
  },
  'cookie-insecure': {
    express: "res.cookie('session', value, { secure: true, httpOnly: true, sameSite: 'lax' });",
    nginx:   'proxy_cookie_flags ~ secure httponly samesite=lax;',
    apache:  'Header always edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"',
    iis:     '<system.web>\n  <httpCookies requireSSL="true" httpOnlyCookies="true" sameSite="Lax" />\n</system.web>',
  },
  'http-no-redirect': {
    nginx:  'server {\n  listen 80;\n  server_name esempio.it;\n  return 301 https://$host$request_uri;\n}',
    apache: 'RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]',
    express: "app.use((req, res, next) => req.secure ? next()\n  : res.redirect(301, 'https://' + req.headers.host + req.url));",
    caddy:  '# Caddy reindirizza su HTTPS automaticamente se il dominio è nel Caddyfile',
    cloudflare: 'SSL/TLS → Edge Certificates → Always Use HTTPS: On',
  },
  'git-exposed': {
    nginx:  'location ~ /\\.(?!well-known) { deny all; }',
    apache: '<DirectoryMatch "/\\.git">\n  Require all denied\n</DirectoryMatch>',
    caddy:  '@hidden path /.git/* /.env\nrespond @hidden 404',
  },
  'env-exposed': {
    nginx:  'location ~ /\\.(?!well-known) { deny all; }',
    apache: '<FilesMatch "^\\.env">\n  Require all denied\n</FilesMatch>',
    caddy:  '@hidden path /.git/* /.env\nrespond @hidden 404',
  },
  'cors-reflect': {
    express: "app.use(cors({ origin: ['https://app.esempio.it'], credentials: true }));",
    nginx:   'map $http_origin $cors_ok { default ""; "https://app.esempio.it" $http_origin; }\nadd_header Access-Control-Allow-Origin $cors_ok always;',
  },
  'security-txt-missing': {
    generic: '# /.well-known/security.txt\nContact: mailto:security@esempio.it\nExpires: 2027-12-31T23:59:59Z\nPreferred-Languages: it, en',
  },
};
SNIPPETS['cookie-no-httponly'] = SNIPPETS['cookie-insecure'];
SNIPPETS['cookie-no-samesite'] = SNIPPETS['cookie-insecure'];
SNIPPETS['cors-reflect-credentials'] = SNIPPETS['cors-reflect'];
SNIPPETS['no-https'] = {
  nginx:  '# certificato gratuito Let\'s Encrypt + redirect automatico\nsudo certbot --nginx -d esempio.it -d www.esempio.it',
  apache: 'sudo certbot --apache -d esempio.it -d www.esempio.it',
  caddy:  '# Caddy ottiene e rinnova i certificati da solo:\nesempio.it {\n  reverse_proxy localhost:3000\n}',
  cloudflare: 'SSL/TLS → Overview → modalità "Full (strict)"\nEdge Certificates → Always Use HTTPS: On',
};
SNIPPETS['generator-version'] = {
  generic: "// WordPress (functions.php)\nremove_action('wp_head', 'wp_generator');\n\n// Joomla (template)\n$this->setGenerator('');\n\n// In generale: aggiorna il CMS all'ultima versione",
};

const FALLBACK_STACKS = ['nginx', 'apache', 'express'];

// Restituisce gli snippet per gli stack rilevati o, se sconosciuti, quelli più comuni.
export function snippetsFor(id, stacks = []) {
  const all = SNIPPETS[id];
  if (!all) return [];
  if (all.generic) return [{ stack: 'generic', label: 'Esempio', code: all.generic }];
  let order = stacks.filter(s => all[s]);
  if (!order.length) order = FALLBACK_STACKS.filter(s => all[s]);
  if (!order.length) order = Object.keys(all).slice(0, 2);
  return order.map(s => ({ stack: s, label: STACK_LABELS[s] || s, code: all[s] }));
}
