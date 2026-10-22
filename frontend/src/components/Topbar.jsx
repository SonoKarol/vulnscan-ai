import { History, Monitor, Moon, ShieldCheck, Sun } from 'lucide-react';

const THEME_ICON = { system: Monitor, dark: Moon, light: Sun };
const THEME_LABEL = { system: 'Tema di sistema', dark: 'Tema scuro', light: 'Tema chiaro' };

export function engineSummary({ status, offline }) {
  if (offline) return { tone: 'bad', text: 'Backend offline' };
  if (!status) return { tone: 'warn', text: 'Connessione…' };
  switch (status.state) {
    case 'ready': return { tone: 'ok', text: `AI pronta · ${status.model.label}` };
    case 'downloading': {
      const p = status.progress;
      return { tone: 'warn', text: p?.total ? `Download modello ${Math.floor((p.downloaded / p.total) * 100)}%` : 'Download modello…' };
    }
    case 'loading': return { tone: 'warn', text: 'Caricamento modello…' };
    case 'error': return { tone: 'bad', text: 'Errore modello AI' };
    case 'disabled': return { tone: '', text: 'AI disattivata' };
    default: return { tone: '', text: 'Modello AI da installare' };
  }
}

export default function Topbar({ engine, theme, historyCount, onHistory, onHome }) {
  const summary = engineSummary(engine);
  const ThemeIcon = THEME_ICON[theme.theme];

  return (
    <header className="topbar">
      <div className="container">
        <button className="brand" onClick={onHome} aria-label="VulnScan AI — torna alla home">
          <span className="brand-mark"><ShieldCheck size={18} /></span>
          <span>VulnScan<span className="brand-accent">AI</span></span>
          <small>v2</small>
        </button>
        <div className="spacer" />
        <button className="pill" onClick={onHome} title="Stato del motore AI embedded">
          <span className={`dot ${summary.tone}`} aria-hidden />
          <span>{summary.text}</span>
        </button>
        <button className="btn btn-ghost btn-icon" onClick={onHistory} title="Storico scansioni" aria-label={`Storico scansioni (${historyCount})`}>
          <History size={18} />
        </button>
        <button className="btn btn-ghost btn-icon" onClick={theme.cycle} title={THEME_LABEL[theme.theme]} aria-label={THEME_LABEL[theme.theme]}>
          <ThemeIcon size={18} />
        </button>
      </div>
    </header>
  );
}
