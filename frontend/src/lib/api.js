async function json(res) {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Errore ${res.status}`);
  return data;
}

export const getStatus = () => fetch('/api/status').then(json);
export const getTor = (refresh = false) => fetch(`/api/status/tor${refresh ? '?refresh=1' : ''}`).then(json);
export const loadModel = () => fetch('/api/ai/load', { method: 'POST' }).then(json);
export const cancelModel = () => fetch('/api/ai/cancel', { method: 'POST' }).then(json);

/**
 * Avvia una scansione e invoca onEvent per ogni evento dello stream NDJSON
 * (step, report, ai-queued, ai-progress, ai, ai-error, error, done).
 */
export async function streamScan(url, { ai = true, signal, onEvent }) {
  const res = await fetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, ai }),
    signal,
  });
  if (!res.ok || !res.body) await json(res);

  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += value;
    let newline;
    while ((newline = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      if (line) onEvent(JSON.parse(line));
    }
  }
}
