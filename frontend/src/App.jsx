import { useEffect, useState } from 'react';
import Topbar from './components/Topbar.jsx';
import Home from './components/Home.jsx';
import ScanView from './components/ScanView.jsx';
import HistoryDrawer from './components/HistoryDrawer.jsx';
import { useEngineStatus, useScan, useTheme } from './lib/hooks.js';
import { loadHistory, saveReport, removeReport, clearHistory, previousScan } from './lib/history.js';
import { TriangleAlert } from 'lucide-react';

export default function App() {
  const engine = useEngineStatus();
  const theme = useTheme();
  const { state, start, reset, open } = useScan();
  const [url, setUrl] = useState('');
  const [history, setHistory] = useState(loadHistory);
  const [drawer, setDrawer] = useState(false);

  // Salva nello storico quando la scansione (AI inclusa) è terminata.
  useEffect(() => {
    if (state.phase === 'done' && state.report && !state.fromHistory) {
      setHistory(h => saveReport(h, state.report));
    }
  }, [state.phase, state.report, state.fromHistory]);

  useEffect(() => { window.scrollTo({ top: 0 }); }, [state.phase === 'idle']);

  const scan = (target, options) => {
    setUrl(target);
    start(target, options);
  };

  const onHome = state.phase === 'idle' || state.phase === 'error';

  return (
    <div className="app">
      <Topbar
        engine={engine}
        theme={theme}
        historyCount={history.length}
        onHistory={() => setDrawer(true)}
        onHome={reset}
      />

      <main>
        <div className="container">
          {onHome ? (
            <Home
              url={url}
              setUrl={setUrl}
              onScan={scan}
              error={state.phase === 'error' ? state.error : null}
              engine={engine}
              history={history}
              onOpen={open}
              onShowHistory={() => setDrawer(true)}
            />
          ) : (
            <ScanView
              state={state}
              previous={state.report ? previousScan(history, state.report) : null}
              onReset={reset}
              onRescan={() => scan(state.report?.target ?? state.target, { ai: state.wantAi })}
            />
          )}
        </div>
      </main>

      <footer className="footer">
        <div className="container">
          <TriangleAlert size={14} aria-hidden />
          Usa VulnScan AI solo su sistemi di tua proprietà o con autorizzazione esplicita: scansionare siti di terzi senza consenso è illegale.
        </div>
      </footer>

      {drawer && (
        <HistoryDrawer
          history={history}
          onClose={() => setDrawer(false)}
          onOpen={report => { open(report); setDrawer(false); }}
          onRemove={id => setHistory(h => removeReport(h, id))}
          onClear={() => setHistory(clearHistory())}
        />
      )}
    </div>
  );
}
