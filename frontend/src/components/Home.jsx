import { useEffect, useState } from 'react';
import { ArrowRight, Cpu, EyeOff, Globe, Lock, RotateCw, ScanLine, ShieldCheck, TriangleAlert, Zap } from 'lucide-react';
import EngineCard from './EngineCard.jsx';
import { useTor } from '../lib/hooks.js';
import { hostOf, isOnionInput, timeAgo } from '../lib/format.js';

export default function Home({ url, setUrl, onScan, error, engine, history, onOpen, onShowHistory }) {
  return (
    <div className="fade-up">
      <section className="hero">
        <span className="eyebrow">Security scanner · AI on-device</span>
        <h1>Trova le falle del tuo sito <em>prima che lo faccia qualcun altro.</em></h1>
        <p>
          Header, TLS, cookie, CORS e file esposti analizzati in pochi secondi. Un modello AI che gira
          dentro l’app spiega i rischi e ti dice cosa correggere per primo — nessun dato lascia il tuo computer.
        </p>
      </section>

      <div className="home-grid">
        <ScanForm url={url} setUrl={setUrl} onScan={onScan} error={error} engine={engine} />
        <div className="side-stack">
          <EngineCard engine={engine} />
          <RecentScans history={history} onOpen={onOpen} onShowAll={onShowHistory} />
        </div>
      </div>

      <section className="features" aria-label="Caratteristiche">
        <div className="card feature">
          <Zap size={20} />
          <h3>Controlli deterministici</h3>
          <p>Oltre 30 controlli con evidenze reali e punteggio riproducibile, indipendente dal modello.</p>
        </div>
        <div className="card feature">
          <Cpu size={20} />
          <h3>AI embedded</h3>
          <p>LLM locale via llama.cpp, accelerato su GPU quando disponibile. Niente Ollama, niente cloud, niente API key.</p>
        </div>
        <div className="card feature">
          <EyeOff size={20} />
          <h3>Clearnet e .onion</h3>
          <p>Scansiona anche i servizi nascosti instradando il traffico attraverso Tor.</p>
        </div>
      </section>
    </div>
  );
}

function ScanForm({ url, setUrl, onScan, error, engine }) {
  const [consent, setConsent] = useState(false);
  const aiReady = engine.status?.state === 'ready';
  const [useAi, setUseAi] = useState(true);
  const onion = isOnionInput(url);
  const { tor, check } = useTor(onion);
  const secure = /^https:\/\//i.test(url.trim());

  useEffect(() => { if (aiReady) setUseAi(true); }, [aiReady]);

  const torBlocked = onion && tor !== 'online';
  const canScan = url.trim() && consent && !torBlocked && !engine.offline;

  function submit(e) {
    e.preventDefault();
    if (canScan) onScan(url.trim(), { ai: aiReady && useAi });
  }

  return (
    <form className="card scan-form" onSubmit={submit} noValidate>
      <div>
        <label htmlFor="target" className="eyebrow">Sito da analizzare</label>
        <div className={`url-field ${onion ? 'onion' : secure ? 'secure' : ''}`} style={{ marginTop: 8 }}>
          <span className="scheme" aria-hidden>
            {onion ? <><EyeOff size={14} /> TOR</> : secure ? <><Lock size={14} /> HTTPS</> : <><Globe size={14} /> URL</>}
          </span>
          <input
            id="target"
            type="text"
            inputMode="url"
            autoComplete="url"
            spellCheck={false}
            autoFocus
            value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder="esempio.it  ·  https://app.esempio.it  ·  xyz….onion"
          />
        </div>
      </div>

      {onion && (
        <div className="notice onion">
          <EyeOff size={18} />
          <div>
            {tor === 'checking' && <p>Verifica della connessione a Tor…</p>}
            {tor === 'online' && <p><strong>Tor attivo.</strong> La scansione passerà dalla rete Tor: i tempi di risposta saranno più lunghi.</p>}
            {(tor === 'offline' || tor === 'unknown') && (
              <>
                <p><strong>Tor non raggiungibile.</strong> Avvia Tor Browser (proxy <code>127.0.0.1:9150</code>) oppure il servizio <code>tor</code> (porta <code>9050</code>) e imposta <code>TOR_PROXY</code> in <code>backend/.env</code>.</p>
                <button type="button" className="btn btn-sm" style={{ marginTop: 10 }} onClick={() => check(true)}>
                  <RotateCw size={14} /> Verifica di nuovo
                </button>
              </>
            )}
          </div>
        </div>
      )}

      <div className="form-row">
        <label className="switch" title={aiReady ? '' : 'Il modello AI non è ancora pronto'}>
          <input type="checkbox" checked={aiReady && useAi} disabled={!aiReady} onChange={e => setUseAi(e.target.checked)} />
          <span className="track" aria-hidden />
          <span>Analisi AI {aiReady ? <span className="dim">· {engine.status.model.label}</span> : <span className="dim">· modello non pronto</span>}</span>
        </label>
        {!aiReady && <span className="form-hint">La scansione funziona anche senza AI.</span>}
      </div>

      <label className="check">
        <input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} />
        <span>Confermo di essere il proprietario del sito o di avere il permesso esplicito del proprietario per effettuare questa scansione.</span>
      </label>

      {error && (
        <div className="notice error" role="alert">
          <TriangleAlert size={18} />
          <div>
            <p><strong>{error.message}</strong></p>
            {error.details?.map((d, i) => <p key={i} className="mono" style={{ fontSize: 12.5 }}>{d}</p>)}
          </div>
        </div>
      )}

      {engine.offline && (
        <div className="notice warn">
          <TriangleAlert size={18} />
          <p>Il backend non risponde. Avvialo con <code>npm run dev</code> dalla cartella del progetto.</p>
        </div>
      )}

      <button type="submit" className={`btn btn-lg ${onion ? 'btn-onion' : 'btn-primary'}`} disabled={!canScan}>
        <ScanLine size={18} />
        {onion ? 'Scansiona via Tor' : 'Avvia scansione'}
        <ArrowRight size={16} />
      </button>
    </form>
  );
}

function RecentScans({ history, onOpen, onShowAll }) {
  if (!history.length) {
    return (
      <div className="card">
        <div className="card-head"><h3>Scansioni recenti</h3></div>
        <div className="empty">
          <ShieldCheck size={22} />
          Le scansioni completate compaiono qui e restano solo in questo browser.
        </div>
      </div>
    );
  }
  return (
    <div className="card">
      <div className="card-head">
        <h3>Scansioni recenti</h3>
        <div className="spacer" />
        {history.length > 4 && <button className="btn btn-ghost btn-sm" onClick={onShowAll}>Vedi tutte</button>}
      </div>
      <ul className="recent-list">
        {history.slice(0, 4).map(r => (
          <li key={r.id}><RecentItem report={r} onOpen={onOpen} /></li>
        ))}
      </ul>
    </div>
  );
}

export function RecentItem({ report, onOpen }) {
  return (
    <button className="recent-item" onClick={() => onOpen(report)}>
      <span className={`grade grade-${report.grade}`}>{report.grade}</span>
      <span className="grow">
        <span className="host">{hostOf(report.finalUrl)}</span>
        <span className="when">{report.score}/100 · {timeAgo(report.scannedAt)}{report.ai ? ' · con AI' : ''}</span>
      </span>
    </button>
  );
}
