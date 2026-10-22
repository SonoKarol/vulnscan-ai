import { useMemo, useState } from 'react';
import {
  ArrowUpRight, Check, ChevronDown, CircleCheck, CircleSlash, Copy, Lock, LockOpen, Minus,
  ShieldCheck, Skull, Sparkles, TriangleAlert, X,
} from 'lucide-react';
import { RISK, SEVERITY, SEVERITY_ORDER, formatDate } from '../lib/format.js';

export default function Report({ report, scan, engine, previous }) {
  return (
    <div className="report">
      <Overview report={report} previous={previous} />
      <AiCard report={report} scan={scan} engine={engine} />
      <Findings report={report} aiPending={scan.phase === 'running' && scan.steps.ai?.status === 'running'} />
      <div className="two-col">
        <HeadersCard headers={report.headers} />
        <div className="report" style={{ gap: 20 }}>
          {report.positives.length > 0 && <PositivesCard positives={report.positives} />}
          {report.tls && !report.tls.error && <TlsCard tls={report.tls} />}
          {report.cookies.length > 0 && <CookiesCard cookies={report.cookies} />}
        </div>
      </div>
      <p className="meta-foot">
        Scansione del {formatDate(report.scannedAt)} · ID <span className="mono">{report.id.slice(0, 8)}</span>
      </p>
    </div>
  );
}

// ─── Overview ────────────────────────────────────────────────────────────────

const GRADE_COLOR = {
  A: 'var(--ok)', B: 'color-mix(in srgb, var(--ok) 55%, var(--sev-medium))',
  C: 'var(--sev-medium)', D: 'var(--sev-high)', F: 'var(--sev-critical)',
};

function ScoreRing({ score, grade }) {
  const r = 64;
  const c = 2 * Math.PI * r;
  return (
    <div className="ring" style={{ '--c': GRADE_COLOR[grade] }} role="img" aria-label={`Punteggio ${score} su 100, voto ${grade}`}>
      <svg width="148" height="148" viewBox="0 0 148 148" aria-hidden>
        <circle className="track" cx="74" cy="74" r={r} fill="none" strokeWidth="10" />
        <circle className="value" cx="74" cy="74" r={r} fill="none" strokeWidth="10" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={c * (1 - score / 100)} />
      </svg>
      <div className="center">
        <div className="score">{score}</div>
        <div className="of">su 100</div>
      </div>
    </div>
  );
}

function Overview({ report, previous }) {
  const total = report.findings.length;
  const delta = previous ? report.score - previous.score : null;
  const tls = report.tls && !report.tls.error ? report.tls : null;

  return (
    <section className="card">
      <div className="overview">
        <ScoreRing score={report.score} grade={report.grade} />
        <div className="overview-main">
          <div className="overview-title">
            <span className={`grade grade-${report.grade}`}>{report.grade}</span>
            <h2>{RISK[report.riskLevel]}</h2>
            {report.isOnion && <span className="badge badge-onion">.ONION</span>}
            {delta != null && delta !== 0 && (
              <span className={`trend ${delta > 0 ? 'up' : 'down'}`} title={`Scansione precedente: ${previous.score}/100`}>
                {delta > 0 ? '▲' : '▼'} {Math.abs(delta)} rispetto alla scansione precedente
              </span>
            )}
          </div>
          <p className="muted">
            {total === 0
              ? 'Nessun problema rilevato dai controlli automatici.'
              : `${total} ${total === 1 ? 'problema rilevato' : 'problemi rilevati'} su header, trasporto, cookie e configurazione del server.`}
          </p>
          {total > 0 && (
            <>
              <div className="sevbar" aria-hidden>
                {SEVERITY_ORDER.filter(s => report.counts[s]).map(s => (
                  <span key={s} className={`sev-${s}`} style={{ flex: report.counts[s] }} />
                ))}
              </div>
              <div className="sevlegend">
                {SEVERITY_ORDER.filter(s => report.counts[s]).map(s => (
                  <span key={s} className={`sev-${s}`}><i />{report.counts[s]} {SEVERITY[s].label.toLowerCase()}</span>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
      <dl className="facts">
        <Fact label="Stato HTTP" value={report.statusCode} />
        <Fact label="Risposta" value={`${report.responseTime} ms`} />
        <Fact label="Trasporto" value={
          <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
            {report.isHttps ? <Lock size={14} color="var(--ok)" /> : <LockOpen size={14} color={report.isOnion ? 'var(--onion)' : 'var(--bad)'} />}
            {tls ? tls.protocol : report.isOnion ? 'Tor' : report.isHttps ? 'HTTPS' : 'HTTP in chiaro'}
          </span>
        } />
        <Fact label="Stack" value={report.tech.stacks.join(' + ') || report.tech.server || 'Non dichiarato'} />
        {report.redirects.length > 1 && <Fact label="Redirect" value={`${report.redirects.length - 1} → ${new URL(report.finalUrl).host}`} />}
      </dl>
    </section>
  );
}

function Fact({ label, value }) {
  return (
    <div className="fact">
      <dt>{label}</dt>
      <dd title={typeof value === 'string' ? value : undefined}>{value}</dd>
    </div>
  );
}

// ─── AI ──────────────────────────────────────────────────────────────────────

function AiCard({ report, scan, engine }) {
  const ai = report.ai;
  const step = scan.steps.ai;
  const generating = scan.phase === 'running' && step?.status === 'running';

  if (ai) {
    return (
      <section className="card ai-card fade-up">
        <div className="ai-head">
          <h2><Sparkles size={17} /> Analisi AI</h2>
          <span className="spacer" />
          <span className="dim" style={{ fontSize: 12.5 }}>
            {ai.model} · in locale · {(ai.durationMs / 1000).toFixed(1)} s
          </span>
        </div>
        <p className="ai-summary">{ai.summary}</p>
        {ai.priorities.length > 0 && (
          <div>
            <h3 className="eyebrow" style={{ marginBottom: 10 }}>Da fare per primo</h3>
            <ol className="priorities">{ai.priorities.map((p, i) => <li key={i}>{p}</li>)}</ol>
          </div>
        )}
      </section>
    );
  }

  if (generating || (scan.phase === 'running' && scan.wantAi && !step)) {
    const summary = scan.aiProgress?.summary;
    return (
      <section className="card ai-card" aria-live="polite" aria-busy="true">
        <div className="ai-head">
          <h2><Sparkles size={17} /> Analisi AI</h2>
          <span className="spacer" />
          <span className="dim mono" style={{ fontSize: 12.5 }}>
            {scan.queued > 0 ? `in coda · posizione ${scan.queued}` : scan.aiProgress ? `${scan.aiProgress.tokens} token` : 'avvio del modello…'}
          </span>
        </div>
        {summary ? (
          <p className="ai-summary">{summary}<span className="cursor" /></p>
        ) : (
          <div className="skeleton"><span style={{ width: '92%' }} /><span style={{ width: '78%' }} /><span style={{ width: '60%' }} /></div>
        )}
        <p className="dim" style={{ fontSize: 12.5 }}>Il report qui sotto è già completo: l’AI aggiunge sintesi, scenari d’attacco e priorità.</p>
      </section>
    );
  }

  if (scan.aiError) {
    return (
      <div className="notice error">
        <TriangleAlert size={18} />
        <p><strong>Analisi AI non riuscita.</strong> {scan.aiError}</p>
      </div>
    );
  }

  const reason = scan.fromHistory
    ? 'Questa scansione è stata salvata senza analisi AI.'
    : step?.detail === 'Disattivata per questa scansione'
      ? 'Analisi AI disattivata per questa scansione.'
      : engine?.state === 'disabled'
        ? 'L’AI è disattivata nella configurazione del backend.'
        : 'Il modello AI non era pronto: installalo dalla home per ottenere sintesi, scenari d’attacco e priorità.';
  return (
    <div className="notice no-print">
      <Sparkles size={18} />
      <p>{reason}</p>
    </div>
  );
}

// ─── Findings ────────────────────────────────────────────────────────────────

function Findings({ report, aiPending }) {
  const [filter, setFilter] = useState('all');
  const present = SEVERITY_ORDER.filter(s => report.counts[s]);
  const list = useMemo(
    () => report.findings.filter(f => filter === 'all' || f.severity === filter),
    [report.findings, filter],
  );

  return (
    <section className="card">
      <div className="card-head">
        <h2>Problemi rilevati</h2>
        <span className="count">{report.findings.length}</span>
      </div>
      {report.findings.length === 0 ? (
        <div className="empty">
          <ShieldCheck size={26} color="var(--ok)" />
          Nessun problema rilevato. Ottimo lavoro!
        </div>
      ) : (
        <>
          {present.length > 1 && (
            <div className="filters" role="toolbar" aria-label="Filtra per gravità">
              <button className="chip" aria-pressed={filter === 'all'} onClick={() => setFilter('all')}>
                Tutti <span className="n">{report.findings.length}</span>
              </button>
              {present.map(s => (
                <button key={s} className={`chip sev-${s}`} aria-pressed={filter === s} onClick={() => setFilter(s)}>
                  {SEVERITY[s].label} <span className="n">{report.counts[s]}</span>
                </button>
              ))}
            </div>
          )}
          <ul className="findings">
            {list.map((f, i) => (
              <FindingItem
                key={f.id}
                finding={f}
                scenario={report.ai?.scenarios?.[f.id]}
                aiPending={aiPending && f.severity !== 'info'}
                defaultOpen={i === 0 && filter === 'all' && ['critical', 'high'].includes(f.severity)}
              />
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

function FindingItem({ finding: f, scenario, aiPending, defaultOpen }) {
  const [open, setOpen] = useState(defaultOpen);
  const id = `finding-${f.id}`;
  return (
    <li className="finding" data-open={open}>
      <button className="finding-row" aria-expanded={open} aria-controls={id} onClick={() => setOpen(o => !o)}>
        <span className={`badge sev-${f.severity}`}>{SEVERITY[f.severity].short}</span>
        <span className="title">{f.title}</span>
        <span className="cat">{scenario && <Sparkles size={13} className="ai-mark" style={{ marginRight: 6, verticalAlign: -2 }} />}{f.category}</span>
        <ChevronDown size={18} className="chev" />
      </button>
      <div className="finding-body" id={id} hidden={!open}>
        <div>
          <p>{f.description}</p>
        </div>
        {f.evidence && (
          <div>
            <h4>Evidenza</h4>
            <div className="evidence">{f.evidence}</div>
          </div>
        )}
        {scenario ? (
          <div className="scenario">
            <h4><Skull size={13} /> Scenario d’attacco · AI</h4>
            <p>{scenario}</p>
          </div>
        ) : aiPending ? (
          <div className="skeleton" aria-label="Scenario in generazione"><span style={{ width: '85%' }} /><span style={{ width: '55%' }} /></div>
        ) : null}
        {f.remediation.length > 0 && (
          <div>
            <h4>Come correggere</h4>
            <CodeBlock snippets={f.remediation} />
          </div>
        )}
        {f.references.length > 0 && (
          <div className="refs">
            {f.references.map(r => (
              <a key={r.url} href={r.url} target="_blank" rel="noopener noreferrer">{r.label} <ArrowUpRight size={13} /></a>
            ))}
          </div>
        )}
      </div>
    </li>
  );
}

function CodeBlock({ snippets }) {
  const [tab, setTab] = useState(0);
  const [copied, setCopied] = useState(false);
  const current = snippets[Math.min(tab, snippets.length - 1)];

  async function copy() {
    try {
      await navigator.clipboard.writeText(current.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {}
  }

  return (
    <div className="code">
      <div className="code-tabs" role="tablist">
        {snippets.map((s, i) => (
          <button key={s.stack} role="tab" aria-selected={i === tab} onClick={() => setTab(i)}>{s.label}</button>
        ))}
        <button className="copy" onClick={copy} aria-label="Copia snippet">
          {copied ? <><Check size={13} /> Copiato</> : <><Copy size={13} /> Copia</>}
        </button>
      </div>
      <pre><code>{current.code}</code></pre>
    </div>
  );
}

// ─── Dettagli ────────────────────────────────────────────────────────────────

const HEADER_ICON = {
  ok: <CircleCheck size={16} className="st-ok" aria-label="OK" />,
  warn: <TriangleAlert size={16} className="st-warn" aria-label="Da migliorare" />,
  missing: <X size={16} className="st-missing" aria-label="Mancante" />,
  na: <CircleSlash size={16} className="st-na" aria-label="Non applicabile" />,
};

function HeadersCard({ headers }) {
  const ok = headers.filter(h => h.status === 'ok').length;
  return (
    <section className="card">
      <div className="card-head">
        <h2>Header di sicurezza</h2>
        <span className="count">{ok}/{headers.length} ok</span>
      </div>
      <table className="table">
        <tbody>
          {headers.map(h => (
            <tr key={h.name}>
              <td className="st">{HEADER_ICON[h.status]}</td>
              <td>
                <span style={{ fontWeight: 550 }}>{h.name}</span>
                {h.note && <span className="dim"> — {h.note}</span>}
                {h.value && <span className="val" title={h.value}>{h.value}</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function PositivesCard({ positives }) {
  return (
    <section className="card">
      <div className="card-head">
        <h2>Configurato bene</h2>
        <span className="count">{positives.length}</span>
      </div>
      <ul className="positives">
        {positives.map(p => (
          <li key={p.id}>
            <CircleCheck size={16} />
            <div><strong>{p.title}</strong><span>{p.description}</span></div>
          </li>
        ))}
      </ul>
    </section>
  );
}

function TlsCard({ tls }) {
  return (
    <section className="card">
      <div className="card-head">
        <h2>Certificato TLS</h2>
        <span className={`badge ${tls.authorized ? 'badge-ok' : 'sev-critical'}`}>{tls.authorized ? 'VALIDO' : 'NON VALIDO'}</span>
      </div>
      <dl className="kv">
        <dt>Protocollo</dt><dd>{tls.protocol} · {tls.cipher}</dd>
        <dt>Soggetto</dt><dd>{tls.subject ?? '—'}</dd>
        <dt>Emittente</dt><dd>{tls.issuer ?? '—'}</dd>
        <dt>Scadenza</dt><dd>{tls.validTo ? `${tls.validTo.slice(0, 10)} (${tls.daysLeft} giorni)` : '—'}</dd>
        {tls.bits && <><dt>Chiave</dt><dd>{tls.keyType ?? ''} {tls.bits} bit</dd></>}
        {tls.authorizationError && <><dt>Errore</dt><dd>{tls.authorizationError}</dd></>}
      </dl>
    </section>
  );
}

const Flag = ({ on, label }) => (
  <span className={`badge ${on ? 'badge-ok' : 'sev-high'}`} style={{ marginRight: 4 }}>
    {on ? <Check size={11} /> : <Minus size={11} />} {label}
  </span>
);

function CookiesCard({ cookies }) {
  return (
    <section className="card">
      <div className="card-head">
        <h2>Cookie</h2>
        <span className="count">{cookies.length}</span>
      </div>
      <table className="table">
        <tbody>
          {cookies.map(c => (
            <tr key={c.name}>
              <td>
                <span className="mono" style={{ fontWeight: 600 }}>{c.name}</span>
                <div style={{ marginTop: 6 }}>
                  <Flag on={c.secure} label="Secure" />
                  <Flag on={c.httpOnly} label="HttpOnly" />
                  <Flag on={!!c.sameSite} label={c.sameSite ? `SameSite=${c.sameSite}` : 'SameSite'} />
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
