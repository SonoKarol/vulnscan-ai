import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import net from 'node:net';
import dns from 'node:dns';
import axios from 'axios';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { config } from '../config.js';

export const USER_AGENT = `VulnScan-AI/${config.version} (Security Audit Tool)`;

export class ScanError extends Error {
  constructor(status, message, details = []) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

// ─── URL helpers ─────────────────────────────────────────────────────────────

export function normalizeUrl(raw) {
  let value = String(raw ?? '').trim();
  if (!value) throw new ScanError(400, 'URL obbligatorio');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) value = 'http://' + value;
  let url;
  try { url = new URL(value); } catch { throw new ScanError(400, 'URL non valido: ' + raw); }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new ScanError(400, 'Sono supportati solo URL http:// e https://');
  }
  url.hash = '';
  return url.href;
}

export function isOnion(url) {
  try { return new URL(url).hostname.endsWith('.onion'); } catch { return false; }
}

// ─── SSRF guard ──────────────────────────────────────────────────────────────
// Lo scanner fa richieste server-side verso URL forniti dall'utente: blocca gli
// indirizzi interni (loopback, RFC-1918, link-local, metadata cloud…) così il
// backend non può essere usato per raggiungere risorse private della rete.

const blocked = new net.BlockList();
for (const [addr, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4],
]) blocked.addSubnet(addr, prefix, 'ipv4');
for (const [addr, prefix] of [
  ['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
]) blocked.addSubnet(addr, prefix, 'ipv6');

// Indirizzi IPv6 che incorporano un IPv4 (IPv4-mapped e NAT64): si valuta l'IPv4.
function embeddedIpv4(address) {
  const dotted = address.match(/^(?:::ffff:|64:ff9b::)(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) return dotted[1];
  const hex = address.match(/^(?:::ffff:|64:ff9b::)([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (!hex) return null;
  const hi = parseInt(hex[1], 16), lo = parseInt(hex[2], 16);
  return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
}

export function isPrivateIp(ip) {
  const address = ip.replace(/^\[|\]$/g, '').toLowerCase();
  if (net.isIPv4(address)) return blocked.check(address, 'ipv4');
  if (!net.isIPv6(address)) return false;
  const v4 = embeddedIpv4(address);
  if (v4) return isPrivateIp(v4);
  return blocked.check(address, 'ipv6');
}

// lookup usato da ogni socket in uscita: la verifica avviene sull'IP a cui ci
// si connette davvero, quindi resiste anche al DNS rebinding.
export function safeLookup(hostname, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    const bad = !config.allowPrivateTargets && addresses.find(a => isPrivateIp(a.address));
    if (bad) {
      const e = new Error(`Target non consentito: ${hostname} risolve a un indirizzo interno (${bad.address})`);
      e.code = 'EBLOCKED';
      return callback(e);
    }
    if (options.all) return callback(null, addresses);
    callback(null, addresses[0].address, addresses[0].family);
  });
}

// Validazione anticipata con messaggi chiari (gli IP letterali non passano dal lookup).
export async function assertPublicTarget(url) {
  if (isOnion(url) || config.allowPrivateTargets) return;
  const hostname = new URL(url).hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) throw new ScanError(400, 'Target non consentito: indirizzo IP interno');
    return;
  }
  let addrs;
  try {
    addrs = await dns.promises.lookup(hostname, { all: true });
  } catch {
    throw new ScanError(422, 'Impossibile risolvere il dominio: ' + hostname);
  }
  if (addrs.some(a => isPrivateIp(a.address))) {
    throw new ScanError(400, 'Target non consentito: il dominio risolve a un indirizzo interno');
  }
}

// ─── Agents ──────────────────────────────────────────────────────────────────

const httpAgent  = new http.Agent({ lookup: safeLookup });
// I certificati vengono valutati a parte (probeTls): un certificato non valido
// è un finding, non un motivo per interrompere la scansione.
const httpsAgent = new https.Agent({ lookup: safeLookup, rejectUnauthorized: false });
let torAgent = null;

function agentsFor(url) {
  if (isOnion(url)) {
    torAgent ??= new SocksProxyAgent(config.torProxy);
    return { httpAgent: torAgent, httpsAgent: torAgent, proxy: false };
  }
  return { httpAgent, httpsAgent, proxy: false };
}

// ─── Requests ────────────────────────────────────────────────────────────────

// Legge al massimo maxBytes del body: agli scanner servono header e l'inizio
// della pagina, non download completi.
async function readBody(stream, maxBytes) {
  const chunks = [];
  let size = 0;
  try {
    for await (const chunk of stream) {
      chunks.push(chunk);
      size += chunk.length;
      if (size >= maxBytes) break;
    }
  } finally {
    stream.destroy();
  }
  return Buffer.concat(chunks).subarray(0, maxBytes).toString('utf8');
}

export async function request(url, { method = 'GET', headers = {}, timeout, maxBytes = 512_000, signal } = {}) {
  const res = await axios.request({
    url, method, signal,
    timeout: timeout ?? (isOnion(url) ? 30_000 : 10_000),
    maxRedirects: 0,                 // i redirect li seguiamo a mano (anti-SSRF)
    responseType: 'stream',
    validateStatus: () => true,
    headers: { 'User-Agent': USER_AGENT, Accept: 'text/html,application/xhtml+xml,*/*;q=0.8', ...headers },
    ...agentsFor(url),
  });
  const body = await readBody(res.data, maxBytes);
  const plain = typeof res.headers?.toJSON === 'function' ? res.headers.toJSON() : { ...res.headers };
  return { url, status: res.status, headers: plain, body };
}

export async function fetchWithRedirects(url, options = {}) {
  const chain = [];
  let current = url;
  for (let hop = 0; hop <= 5; hop++) {
    await assertPublicTarget(current);
    const res = await request(current, options);
    chain.push({ url: current, status: res.status });
    const location = res.headers.location;
    if (res.status >= 300 && res.status < 400 && location) {
      if (hop === 5) throw new Error('Troppi redirect (>5)');
      current = new URL(location, current).href;
      continue;
    }
    return { ...res, chain };
  }
}

// ─── TLS ─────────────────────────────────────────────────────────────────────

export function probeTls(url, timeout = 8000) {
  const { hostname, port } = new URL(url);
  const host = hostname.replace(/^\[|\]$/g, '');
  return new Promise(resolve => {
    const socket = tls.connect({
      host, port: Number(port) || 443,
      servername: net.isIP(host) ? undefined : host,
      lookup: safeLookup,
      rejectUnauthorized: false,
      timeout,
    }, () => {
      const cert = socket.getPeerCertificate();
      const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
      resolve({
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name ?? null,
        subject: cert.subject?.CN ?? null,
        issuer: cert.issuer?.O || cert.issuer?.CN || null,
        validFrom: cert.valid_from ? new Date(cert.valid_from).toISOString() : null,
        validTo: validTo ? validTo.toISOString() : null,
        daysLeft: validTo ? Math.floor((validTo - Date.now()) / 86_400_000) : null,
        bits: cert.bits ?? null,
        keyType: cert.asn1Curve || cert.nistCurve ? 'EC' : cert.modulus ? 'RSA' : null,
      });
      socket.end();
    });
    socket.on('error', err => resolve({ error: err.message }));
    socket.on('timeout', () => { socket.destroy(); resolve({ error: 'Timeout handshake TLS' }); });
  });
}

// ─── Tor ─────────────────────────────────────────────────────────────────────

let torCache = { at: 0, online: false };

export async function checkTor({ force = false } = {}) {
  if (!force && Date.now() - torCache.at < 30_000) return torCache.online;
  let online = false;
  try {
    const agent = new SocksProxyAgent(config.torProxy);
    const res = await axios.get('https://check.torproject.org/api/ip', {
      httpAgent: agent, httpsAgent: agent, proxy: false, timeout: 10_000,
    });
    online = res.data?.IsTor === true;
  } catch {}
  torCache = { at: Date.now(), online };
  return online;
}
