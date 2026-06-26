import { useState, useEffect } from 'react';

export default function ScanForm({ onScan, error }) {
  const [url, setUrl]     = useState('');
  const [agreed, setAgreed] = useState(false);
  const [status, setStatus] = useState({ ollama: 'checking', tor: 'checking' });

  const isOnion = url.trim().replace(/^https?:\/\//i, '').endsWith('.onion');

  useEffect(() => {
    fetch('/api/scan/health')
      .then(r => r.json())
      .then(d => setStatus({ ollama: d.ollama, tor: d.tor }))
      .catch(() => setStatus({ ollama: 'offline', tor: 'offline' }));
  }, []);

  const ollamaOk = status.ollama === 'online';
  const torOk    = status.tor    === 'online';
  const canScan  = url.trim() && agreed && ollamaOk && (!isOnion || torOk);

  function handleSubmit(e) {
    e.preventDefault();
    if (canScan) onScan(url.trim());
  }

  return (
    <div style={{ paddingTop: 80, animation: 'fadeIn 0.4s ease' }}>

      <div style={{ marginBottom: 48 }}>
        <p style={{ color: 'var(--text-dim)', fontSize: 11, letterSpacing: '0.2em', marginBottom: 12 }}>
          // SECURITY SCANNER — FREE & LOCAL
        </p>
        <h1 style={{ fontSize: 36, fontWeight: 300, lineHeight: 1.2, letterSpacing: '-0.02em', fontFamily: 'var(--font-mono)' }}>
          Analisi vulnerabilità<br />
          <span style={{ color: 'var(--accent)' }}>clearnet + darknet</span>
        </h1>
        <p style={{ marginTop: 16, color: 'var(--text-mid)', fontFamily: 'var(--font-sans)', fontSize: 14, maxWidth: 480 }}>
          Scansiona siti normali o servizi nascosti <code style={{ color: 'var(--accent)' }}>.onion</code> sulla rete Tor. AI locale, zero costi, zero cloud.
        </p>
      </div>

      {/* Status badges */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 24, flexWrap: 'wrap' }}>
        <StatusBadge label="Ollama" status={status.ollama}
          onlineText="AI pronta"
          offlineText="esegui: ollama serve"
        />
        <StatusBadge label="Tor" status={status.tor}
          onlineText="rete Tor attiva"
          offlineText="richiesto per .onion"
          optional={!isOnion}
        />
      </div>

      {/* Tor offline hint — mostrato solo se l'utente sta inserendo un .onion */}
      {isOnion && !torOk && status.tor !== 'checking' && (
        <div style={{ marginBottom: 20, padding: '12px 16px', background: 'rgba(255,68,68,0.05)', border: '1px solid rgba(255,68,68,0.2)', fontSize: 12, fontFamily: 'var(--font-sans)', lineHeight: 1.8, color: 'var(--text-mid)', animation: 'fadeIn 0.3s ease' }}>
          <p style={{ color: 'var(--red)', fontFamily: 'var(--font-mono)', marginBottom: 6 }}>// Come avviare Tor</p>
          <p><strong style={{ color: 'var(--text)' }}>Opzione A (più semplice)</strong> — Scarica e avvia <strong style={{ color: 'var(--text)' }}>Tor Browser</strong> da <code style={{ color: 'var(--accent)' }}>torproject.org</code>. Tienilo aperto. Proxy SOCKS5 su <code style={{ color: 'var(--accent)' }}>127.0.0.1:9150</code>.</p>
          <p><strong style={{ color: 'var(--text)' }}>Opzione B (avanzata)</strong> — Installa il servizio Tor e avvialo con <code style={{ color: 'var(--accent)', background: 'rgba(0,255,136,0.07)', padding: '1px 5px' }}>tor</code> da terminale. Proxy SOCKS5 su <code style={{ color: 'var(--accent)' }}>127.0.0.1:9050</code>.</p>
          <p style={{ marginTop: 4 }}>Imposta <code style={{ color: 'var(--accent)' }}>TOR_PROXY</code> nel file <code style={{ color: 'var(--accent)' }}>backend/.env</code> sulla porta corrispondente (default <code style={{ color: 'var(--accent)' }}>9150</code>, Tor Browser).</p>
        </div>
      )}

      {/* Ollama offline hint */}
      {!ollamaOk && status.ollama !== 'checking' && (
        <div style={{ marginBottom: 20, padding: '12px 16px', background: 'rgba(255,68,68,0.05)', border: '1px solid rgba(255,68,68,0.2)', fontSize: 12, fontFamily: 'var(--font-sans)', lineHeight: 1.8, color: 'var(--text-mid)', animation: 'fadeIn 0.3s ease' }}>
          <p style={{ color: 'var(--red)', fontFamily: 'var(--font-mono)', marginBottom: 6 }}>// Come avviare Ollama</p>
          <p>1. Scarica da <strong style={{ color: 'var(--text)' }}>ollama.com</strong></p>
          <p>2. <code style={{ color: 'var(--accent)', background: 'rgba(0,255,136,0.07)', padding: '1px 5px' }}>ollama pull mistral</code></p>
          <p>3. <code style={{ color: 'var(--accent)', background: 'rgba(0,255,136,0.07)', padding: '1px 5px' }}>ollama serve</code></p>
        </div>
      )}

      {/* Form */}
      <form onSubmit={handleSubmit}>
        <div style={{ display: 'flex', marginBottom: 20, border: `1px solid ${isOnion ? 'rgba(160,100,255,0.4)' : 'var(--border-bright)'}`, borderRadius: 'var(--radius)', opacity: !ollamaOk ? 0.5 : 1 }}>
          <span style={{ padding: '12px 14px', color: isOnion ? '#a064ff' : 'var(--accent)', borderRight: `1px solid ${isOnion ? 'rgba(160,100,255,0.4)' : 'var(--border-bright)'}`, display: 'flex', alignItems: 'center', fontSize: 13, whiteSpace: 'nowrap' }}>
            {isOnion ? 'TOR://' : 'TARGET://'}
          </span>
          <input
            type="text"
            value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder="esempio.com  oppure  abcdef1234567890.onion"
            disabled={!ollamaOk}
            style={{ flex: 1, background: 'transparent', border: 'none', outline: 'none', color: 'var(--text)', fontFamily: 'var(--font-mono)', fontSize: 14, padding: '12px 16px' }}
            autoFocus
          />
          {isOnion && (
            <span style={{ padding: '12px 12px', display: 'flex', alignItems: 'center', fontSize: 16 }} title="Sito .onion — verrà usata la rete Tor">🧅</span>
          )}
        </div>

        <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginBottom: 28, cursor: 'pointer' }}>
          <input type="checkbox" checked={agreed} onChange={e => setAgreed(e.target.checked)} style={{ marginTop: 2, accentColor: 'var(--accent)' }} />
          <span style={{ color: 'var(--text-mid)', fontSize: 12, fontFamily: 'var(--font-sans)', lineHeight: 1.5 }}>
            Confermo di essere il proprietario di questo sito o di avere il permesso esplicito del proprietario per effettuare questa scansione.
          </span>
        </label>

        <button type="submit" disabled={!canScan} style={{
          background:    canScan ? (isOnion ? '#a064ff' : 'var(--accent)') : 'transparent',
          color:         canScan ? '#000' : 'var(--text-dim)',
          border:        `1px solid ${canScan ? (isOnion ? '#a064ff' : 'var(--accent)') : 'var(--border)'}`,
          fontFamily:    'var(--font-mono)', fontWeight: 600, fontSize: 13,
          padding:       '12px 32px', cursor: canScan ? 'pointer' : 'not-allowed',
          letterSpacing: '0.1em', transition: 'all var(--transition)', borderRadius: 'var(--radius)',
        }}>
          {isOnion ? '🧅 SCAN .ONION →' : 'AVVIA SCANSIONE →'}
        </button>
      </form>

      {error && (
        <div style={{ marginTop: 24, padding: '12px 16px', border: '1px solid var(--red)', color: 'var(--red)', fontSize: 13, animation: 'fadeIn 0.3s ease' }}>
          ✕ {error}
        </div>
      )}

      {/* Info cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 1, marginTop: 64, background: 'var(--border)' }}>
        {[
          { icon: '◈', label: 'Clearnet',        desc: 'Qualsiasi sito HTTP/HTTPS, indicizzato o no' },
          { icon: '🧅', label: 'Darknet (.onion)', desc: 'Servizi nascosti Tor — richiede Tor Browser attivo' },
          { icon: '◉', label: 'AI Locale',        desc: 'Mistral/Llama via Ollama — nessun dato inviato al cloud' },
        ].map(c => (
          <div key={c.label} style={{ background: 'var(--bg-card)', padding: '20px 18px' }}>
            <span style={{ fontSize: 16 }}>{c.icon}</span>
            <p style={{ marginTop: 10, fontWeight: 500, fontSize: 12, letterSpacing: '0.05em' }}>{c.label}</p>
            <p style={{ marginTop: 4, color: 'var(--text-mid)', fontSize: 11, fontFamily: 'var(--font-sans)', lineHeight: 1.5 }}>{c.desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function StatusBadge({ label, status, onlineText, offlineText, optional }) {
  const isOnline   = status === 'online';
  const isChecking = status === 'checking';
  const color = isOnline ? 'var(--accent)' : optional ? 'var(--text-dim)' : 'var(--red)';
  const borderColor = isOnline ? 'var(--accent)' : optional ? 'var(--border-bright)' : 'var(--red)';

  return (
    <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '6px 12px', border: `1px solid ${borderColor}`, borderRadius: 'var(--radius)' }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', flexShrink: 0, background: color, animation: isChecking ? 'pulse 1s infinite' : 'none' }} />
      <span style={{ fontSize: 11, letterSpacing: '0.08em', color }}>
        <strong>{label}</strong> — {isChecking ? 'verifica...' : isOnline ? onlineText : offlineText}
      </span>
    </div>
  );
}
