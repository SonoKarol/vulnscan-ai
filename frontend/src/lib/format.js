export const SEVERITY = {
  critical: { label: 'Critica', short: 'CRIT' },
  high:     { label: 'Alta',    short: 'ALTA' },
  medium:   { label: 'Media',   short: 'MEDIA' },
  low:      { label: 'Bassa',   short: 'BASSA' },
  info:     { label: 'Info',    short: 'INFO' },
};
export const SEVERITY_ORDER = Object.keys(SEVERITY);

export const RISK = {
  critical: 'Rischio critico',
  high: 'Rischio alto',
  medium: 'Rischio medio',
  low: 'Rischio basso',
  none: 'Nessun rischio rilevato',
};

export function hostOf(url) {
  try { return new URL(url).host; } catch { return url; }
}

export function isOnionInput(value) {
  const host = value.trim().replace(/^[a-z]+:\/\//i, '').split(/[/:?#]/)[0];
  return host.endsWith('.onion');
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return '—';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
  return `${bytes.toFixed(i >= 2 ? 1 : 0)} ${units[i]}`;
}

const dateFmt = new Intl.DateTimeFormat('it-IT', { dateStyle: 'medium', timeStyle: 'short' });
export const formatDate = iso => dateFmt.format(new Date(iso));

const rtf = new Intl.RelativeTimeFormat('it', { numeric: 'auto' });
export function timeAgo(iso) {
  const diff = (new Date(iso) - Date.now()) / 1000;
  const steps = [[60, 'second'], [3600, 'minute'], [86400, 'hour'], [604800, 'day'], [2629800, 'week'], [31557600, 'month'], [Infinity, 'year']];
  let prev = 1;
  for (const [limit, unit] of steps) {
    if (Math.abs(diff) < limit) return rtf.format(Math.round(diff / prev), unit);
    prev = limit;
  }
}
