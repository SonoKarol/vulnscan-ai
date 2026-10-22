import { useEffect, useRef } from 'react';
import { History, Trash2, X } from 'lucide-react';
import { RecentItem } from './Home.jsx';

export default function HistoryDrawer({ history, onClose, onOpen, onRemove, onClear }) {
  const panel = useRef(null);
  const close = useRef(onClose);
  close.current = onClose;

  useEffect(() => {
    const esc = e => { if (e.key === 'Escape') close.current(); };
    document.addEventListener('keydown', esc);
    panel.current?.focus();
    return () => document.removeEventListener('keydown', esc);
  }, []);

  return (
    <>
      <div className="overlay" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-labelledby="history-title" tabIndex={-1} ref={panel}>
        <div className="drawer-head">
          <History size={18} />
          <h2 id="history-title">Storico scansioni</h2>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={onClose} aria-label="Chiudi"><X size={18} /></button>
        </div>
        <div className="drawer-body">
          {history.length === 0 ? (
            <div className="empty">Nessuna scansione salvata.</div>
          ) : (
            <ul className="recent-list">
              {history.map(r => (
                <li key={r.id} className="recent-row">
                  <RecentItem report={r} onOpen={onOpen} />
                  <button className="btn btn-ghost btn-icon btn-sm" onClick={() => onRemove(r.id)} aria-label={`Elimina scansione di ${r.finalUrl}`} title="Elimina">
                    <Trash2 size={15} />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
        {history.length > 0 && (
          <div className="drawer-foot">
            <span className="dim" style={{ fontSize: 12.5, marginRight: 'auto', alignSelf: 'center' }}>Salvato solo in questo browser</span>
            <button className="btn btn-sm" onClick={() => { if (confirm('Eliminare tutte le scansioni salvate?')) onClear(); }}>
              <Trash2 size={14} /> Svuota
            </button>
          </div>
        )}
      </aside>
    </>
  );
}
