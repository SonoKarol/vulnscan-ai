import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, Check, ChevronDown, Circle, Download, FileJson, FileText, LoaderCircle, Minus, Printer, RotateCw, X } from 'lucide-react';
import Report from './Report.jsx';
import { exportJson, exportMarkdown } from '../lib/export.js';

const STEPS = [
  { id: 'resolve', label: 'Risoluzione del target' },
  { id: 'fetch', label: 'Richiesta HTTP e redirect' },
  { id: 'tls', label: 'TLS, HTTPS e file esposti' },
  { id: 'analyze', label: 'Controlli di sicurezza' },
  { id: 'ai', label: 'Analisi AI embedded' },
];

const STEP_ICON = {
  pending: <Circle size={10} />,
  running: <LoaderCircle size={15} className="spin" />,
  done: <Check size={15} />,
  skipped: <Minus size={15} />,
  error: <X size={15} />,
};

export default function ScanView({ state, engine, previous, onReset, onRescan }) {
  const { report, phase } = state;
  const running = phase === 'running';

  return (
    <div className="fade-up">
      <div className="scan-toolbar">
        <button className="btn btn-ghost btn-icon" onClick={onReset} aria-label="Nuova scansione" title="Nuova scansione">
          <ArrowLeft size={18} />
        </button>
        <div className="target">
          <span className="eyebrow">{running ? 'Scansione in corso' : state.fromHistory ? 'Dallo storico' : 'Report'}</span>
          <span className="url" title={report?.finalUrl ?? state.target}>{report?.finalUrl ?? state.target}</span>
        </div>
        <div className="actions">
          {report && !running && (
            <button className="btn" onClick={onRescan}><RotateCw size={15} /> Ripeti</button>
          )}
          {report && !running && <ExportMenu report={report} />}
        </div>
      </div>

      {!report ? (
        <div className="scan-running">
          <ProgressCard steps={state.steps} />
        </div>
      ) : (
        <Report report={report} scan={state} engine={engine} previous={previous} />
      )}
    </div>
  );
}

function ProgressCard({ steps }) {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    const started = Date.now();
    const t = setInterval(() => setElapsed(Date.now() - started), 100);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="card" aria-live="polite">
      <div className="card-head">
        <LoaderCircle size={16} className="spin" style={{ color: 'var(--accent)' }} />
        <h2>Analisi in corso</h2>
        <div className="spacer" />
        <span className="mono dim">{(elapsed / 1000).toFixed(1)} s</span>
      </div>
      <ol className="steps">
        {STEPS.map(s => {
          const st = steps[s.id]?.status ?? 'pending';
          return (
            <li key={s.id} className={`step ${st}`}>
              <span className="icon">{STEP_ICON[st]}</span>
              <span>{s.label}</span>
              <span className="detail">{steps[s.id]?.detail ?? ''}</span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function ExportMenu({ report }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    const close = e => { if (!ref.current?.contains(e.target)) setOpen(false); };
    const esc = e => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('pointerdown', close);
    document.addEventListener('keydown', esc);
    return () => { document.removeEventListener('pointerdown', close); document.removeEventListener('keydown', esc); };
  }, [open]);

  const run = fn => () => { setOpen(false); fn(); };

  return (
    <div className="menu" ref={ref}>
      <button className="btn" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(o => !o)}>
        <Download size={15} /> Esporta <ChevronDown size={14} />
      </button>
      {open && (
        <div className="menu-list" role="menu">
          <button role="menuitem" onClick={run(() => exportMarkdown(report))}><FileText size={16} /> Markdown (.md)</button>
          <button role="menuitem" onClick={run(() => exportJson(report))}><FileJson size={16} /> JSON</button>
          <button role="menuitem" onClick={run(() => setTimeout(() => window.print(), 50))}><Printer size={16} /> Stampa / PDF</button>
        </div>
      )}
    </div>
  );
}
