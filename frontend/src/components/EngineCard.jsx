import { useState } from 'react';
import { CircleCheck, Download, LoaderCircle, RotateCw, ServerOff, TriangleAlert, X } from 'lucide-react';
import { cancelModel, loadModel } from '../lib/api.js';
import { formatBytes } from '../lib/format.js';

const GPU_LABEL = { cuda: 'NVIDIA CUDA', vulkan: 'Vulkan', metal: 'Apple Metal', cpu: 'Solo CPU' };

export default function EngineCard({ engine }) {
  const { status, offline, refresh } = engine;
  const [busy, setBusy] = useState(false);

  async function act(fn) {
    setBusy(true);
    try { await fn(); } catch {} finally { setBusy(false); refresh(); }
  }

  if (offline) {
    return (
      <div className="card engine">
        <Head icon={<ServerOff size={20} />} title="Backend non raggiungibile" sub="Avvia il server per usare lo scanner" tone="bad" />
      </div>
    );
  }
  if (!status) {
    return (
      <div className="card engine">
        <Head icon={<LoaderCircle size={20} className="spin" />} title="Motore AI" sub="Verifica dello stato…" />
      </div>
    );
  }

  const { model, state, progress } = status;
  const pct = progress?.total ? (progress.downloaded / progress.total) * 100 : null;

  return (
    <div className="card engine" aria-live="polite">
      {state === 'ready' && (
        <>
          <Head icon={<CircleCheck size={20} />} title="Modello AI pronto" sub="Usato al posto dell’analista integrato, sempre in locale" />
          <dl className="engine-meta">
            <dt>Modello</dt><dd>{model.label}</dd>
            <dt>Accelerazione</dt><dd>{GPU_LABEL[status.gpu] ?? status.gpu}</dd>
            {model.size && <><dt>Dimensione</dt><dd>{formatBytes(model.size)}</dd></>}
            {status.queue > 0 && <><dt>In coda</dt><dd>{status.queue} analisi</dd></>}
          </dl>
        </>
      )}

      {state === 'idle' && (
        <>
          <Head icon={<CircleCheck size={20} />} title="Analista integrato attivo" sub="Analisi istantanea, nessun download richiesto" />
          <p className="muted" style={{ fontSize: 13.5 }}>
            Vuoi testi più ricchi e discorsivi? Puoi aggiungere un modello AI locale
            ({model.label}{model.sizeHint ? `, ${model.sizeHint}` : ''}). È del tutto facoltativo.
          </p>
          <div className="engine-actions">
            <button className="btn btn-sm" disabled={busy} onClick={() => act(loadModel)}>
              <Download size={14} /> Scarica modello AI (opzionale)
            </button>
          </div>
        </>
      )}

      {state === 'downloading' && (
        <>
          <Head icon={<Download size={20} />} title="Download del modello" sub={model.label} />
          <div className={`progress ${pct == null ? 'indeterminate' : ''}`} role="progressbar" aria-valuenow={pct ? Math.round(pct) : undefined} aria-valuemin={0} aria-valuemax={100}>
            <span style={{ width: `${pct ?? 0}%` }} />
          </div>
          <div className="form-row" style={{ fontSize: 13 }}>
            <span className="muted">
              {progress ? `${formatBytes(progress.downloaded)} di ${formatBytes(progress.total)}` : 'Preparazione…'}
            </span>
            <span className="mono">{pct != null ? `${pct.toFixed(1)}%` : ''}</span>
          </div>
          <div className="engine-actions">
            <button className="btn btn-sm" disabled={busy} onClick={() => act(cancelModel)}><X size={14} /> Annulla</button>
          </div>
        </>
      )}

      {state === 'loading' && (
        <>
          <Head icon={<LoaderCircle size={20} className="spin" />} title="Caricamento in memoria" sub={`${model.label} · qualche secondo`} />
          <div className="progress indeterminate"><span /></div>
        </>
      )}

      {state === 'error' && (
        <>
          <Head icon={<TriangleAlert size={20} />} title="Modello AI non disponibile" sub={`${model.label} · l’analista integrato resta attivo`} tone="bad" />
          <p className="mono" style={{ fontSize: 12.5, color: 'var(--text-2)', overflowWrap: 'anywhere' }}>{status.error}</p>
          <div className="engine-actions">
            <button className="btn btn-sm" disabled={busy} onClick={() => act(loadModel)}><RotateCw size={14} /> Riprova</button>
          </div>
        </>
      )}

      {state === 'disabled' && (
        <Head icon={<CircleCheck size={20} />} title="Analista integrato attivo" sub="Modello AI opzionale disattivato (AI_ENABLED=false)" />
      )}

      {['ready', 'error'].includes(state) && (
        <p className="dim" style={{ fontSize: 12.5 }}>
          Modello opzionale: cambialo con <code>AI_MODEL</code> in <code>backend/.env</code>: {status.presets.map(p => p.id).join(' · ')} o qualsiasi GGUF.
        </p>
      )}
    </div>
  );
}

function Head({ icon, title, sub, tone }) {
  const color = tone === 'bad' ? 'var(--bad)' : undefined;
  return (
    <div className="engine-head">
      <span className="engine-icon" style={color ? { color, background: 'color-mix(in srgb, var(--bad) 12%, transparent)' } : undefined}>{icon}</span>
      <div>
        <h3>{title}</h3>
        <p>{sub}</p>
      </div>
    </div>
  );
}
