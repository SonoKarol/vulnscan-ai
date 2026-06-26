import { useState } from 'react';

const SEVERITY_COLORS = {
  critical: '#ff4444',
  high:     '#ff8800',
  medium:   '#ffcc00',
  low:      '#4488ff',
  info:     '#888',
};

const RISK_LABELS = {
  critical: 'CRITICO',
  high:     'ALTO',
  medium:   'MEDIO',
  low:      'BASSO',
};

export default function ScanReport({ report, onReset }) {
  const score    = report.score ?? 0;
  const riskColor = SEVERITY_COLORS[report.risk_level] || '#888';

  return (
    <div style={{ paddingTop: 40, animation: 'fadeIn 0.5s ease' }}>

      {/* Toolbar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 32 }}>
        <div>
          <p style={{ color: 'var(--text-dim)', fontSize: 11, letterSpacing: '0.15em' }}>// REPORT</p>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 4 }}>
            {report.isOnion && <span style={{ fontSize: 11, padding: "1px 8px", border: "1px solid #a064ff", color: "#a064ff", borderRadius: 2, letterSpacing: "0.08em" }}>🧅 .ONION</span>}
            <p style={{ fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text-mid)" }}>{report.target}</p>
          </div>
        </div>
        <button onClick={onReset} style={{ background: 'transparent', border: '1px solid var(--border-bright)', color: 'var(--text-mid)', fontFamily: 'var(--font-mono)', fontSize: 12, padding: '8px 18px', cursor: 'pointer', letterSpacing: '0.08em' }}>
          ← NUOVA SCANSIONE
        </button>
      </div>

      {/* Score row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr 1fr 1fr', gap: 1, background: 'var(--border)', marginBottom: 1 }}>
        <ScoreBox score={score} riskColor={riskColor} riskLabel={RISK_LABELS[report.risk_level]} />
        <InfoBox label="STATUS"   value={report.statusCode} />
        <InfoBox label="RISPOSTA" value={`${report.responseTime}ms`} />
        <InfoBox label="VULNS"    value={report.vulnerabilities?.length ?? 0} accent={report.vulnerabilities?.length > 0} />
      </div>

      {/* Summary */}
      <div style={{ background: 'var(--bg-card)', padding: '16px 18px', marginBottom: 1, borderLeft: `3px solid ${riskColor}` }}>
        <p style={{ color: 'var(--text-dim)', fontSize: 11, letterSpacing: '0.1em', marginBottom: 6 }}>SOMMARIO</p>
        <p style={{ fontFamily: 'var(--font-sans)', fontSize: 13, lineHeight: 1.6, color: 'var(--text)' }}>{report.summary}</p>
      </div>

      {/* Server info */}
      {(report.serverInfo?.server || report.serverInfo?.poweredBy) && (
        <div style={{ background: 'var(--bg-card)', padding: '12px 18px', marginBottom: 24, display: 'flex', gap: 24 }}>
          {report.serverInfo.server    && <InfoPill label="SERVER"       value={report.serverInfo.server}    warn />}
          {report.serverInfo.poweredBy && <InfoPill label="X-POWERED-BY" value={report.serverInfo.poweredBy} warn />}
        </div>
      )}

      {/* Header checks */}
      <Section title="HEADER DI SICUREZZA" count={report.headerChecks?.length}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1, background: 'var(--border)' }}>
          {report.headerChecks?.map(h => (
            <div key={h.header} style={{ background: 'var(--bg-card)', padding: '12px 14px', display: 'flex', gap: 10, alignItems: 'flex-start' }}>
              <span style={{ color: h.status === 'present' ? 'var(--accent)' : 'var(--red)', fontSize: 10, marginTop: 2 }}>
                {h.status === 'present' ? '✓' : '✕'}
              </span>
              <div>
                <p style={{ fontSize: 11, fontWeight: 500, letterSpacing: '0.05em' }}>{h.name}</p>
                <p style={{ fontSize: 10, color: 'var(--text-dim)', marginTop: 2 }}>
                  {h.value ? h.value.slice(0, 60) + (h.value.length > 60 ? '…' : '') : h.description}
                </p>
              </div>
            </div>
          ))}
        </div>
      </Section>

      {/* Vulnerabilities */}
      {report.vulnerabilities?.length > 0 && (
        <Section title="VULNERABILITÀ RILEVATE" count={report.vulnerabilities.length}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 1, background: 'var(--border)' }}>
            {report.vulnerabilities.map(v => <VulnCard key={v.id} vuln={v} />)}
          </div>
        </Section>
      )}

      {/* Positive findings */}
      {report.positive_findings?.length > 0 && (
        <Section title="ELEMENTI POSITIVI">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1, background: 'var(--border)' }}>
            {report.positive_findings.map((f, i) => (
              <div key={i} style={{ background: 'var(--bg-card)', padding: '12px 14px', borderLeft: '3px solid var(--accent)' }}>
                <p style={{ fontSize: 12, fontWeight: 500 }}>✓ {f.title}</p>
                <p style={{ fontSize: 11, color: 'var(--text-mid)', fontFamily: 'var(--font-sans)', marginTop: 4, lineHeight: 1.5 }}>{f.description}</p>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Recommendations */}
      {report.recommendations?.length > 0 && (
        <Section title="RACCOMANDAZIONI PRIORITARIE">
          {report.recommendations.map((r, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ color: 'var(--accent)', fontSize: 11 }}>{String(i + 1).padStart(2, '0')}.</span>
              <span style={{ fontFamily: 'var(--font-sans)', fontSize: 13, color: 'var(--text-mid)', lineHeight: 1.5 }}>{r}</span>
            </div>
          ))}
        </Section>
      )}

      <p style={{ marginTop: 32, textAlign: 'center', color: 'var(--text-dim)', fontSize: 10, letterSpacing: '0.1em' }}>
        Scansione completata: {new Date(report.scannedAt).toLocaleString('it-IT')}
      </p>
    </div>
  );
}

// ─── VulnCard con 3 tab ───────────────────────────────────────────────────────

function VulnCard({ vuln }) {
  const [open, setOpen]     = useState(false);
  const [tab,  setTab]      = useState('description');
  const color = SEVERITY_COLORS[vuln.severity] || '#888';

  const tabs = [
    { id: 'description',      label: '📋 Descrizione' },
    { id: 'exploit_scenario', label: '💀 Come viene sfruttata' },
    { id: 'remediation',      label: '🔧 Come correggerla' },
  ];

  const tabContent = {
    description:      { text: vuln.description,      accent: false,  emptyMsg: 'Nessuna descrizione disponibile.' },
    exploit_scenario: { text: vuln.exploit_scenario, accent: false,  emptyMsg: 'Nessuno scenario fornito dal modello.', highlight: true },
    remediation:      { text: vuln.remediation,      accent: true,   emptyMsg: 'Nessuna remediation disponibile.' },
  };

  return (
    <div style={{ background: 'var(--bg-card)', borderLeft: `3px solid ${color}` }}>

      {/* Header row — click to expand */}
      <button
        onClick={() => setOpen(o => !o)}
        style={{ width: '100%', background: 'transparent', border: 'none', cursor: 'pointer', padding: '14px 16px', display: 'flex', alignItems: 'center', gap: 12, textAlign: 'left' }}
      >
        <span style={{ fontSize: 9, padding: '2px 8px', border: `1px solid ${color}`, color, letterSpacing: '0.1em', flexShrink: 0 }}>
          {(vuln.severity || 'info').toUpperCase()}
        </span>
        <span style={{ flex: 1, color: 'var(--text)', fontSize: 13, fontFamily: 'var(--font-mono)' }}>{vuln.title}</span>
        <span style={{ color: 'var(--text-dim)', fontSize: 10 }}>{vuln.category}</span>
        <span style={{ color: 'var(--text-dim)', fontSize: 12, marginLeft: 8 }}>{open ? '▲' : '▼'}</span>
      </button>

      {/* Expanded content */}
      {open && (
        <div style={{ borderTop: '1px solid var(--border)', animation: 'fadeIn 0.2s ease' }}>

          {/* Tab bar */}
          <div style={{ display: 'flex', borderBottom: '1px solid var(--border)' }}>
            {tabs.map(t => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                style={{
                  background:   tab === t.id ? 'var(--bg-hover)' : 'transparent',
                  border:       'none',
                  borderBottom: tab === t.id ? `2px solid ${t.id === 'exploit_scenario' ? 'var(--red)' : t.id === 'remediation' ? 'var(--accent)' : 'var(--text-mid)'}` : '2px solid transparent',
                  color:        tab === t.id ? 'var(--text)' : 'var(--text-dim)',
                  fontFamily:   'var(--font-mono)',
                  fontSize:     11,
                  padding:      '10px 16px',
                  cursor:       'pointer',
                  letterSpacing:'0.05em',
                  transition:   'all var(--transition)',
                  flex: 1,
                }}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Tab body */}
          <div style={{ padding: '16px' }}>
            {tab === 'exploit_scenario' && (
              <div style={{ background: 'rgba(255,68,68,0.05)', border: '1px solid rgba(255,68,68,0.15)', borderRadius: 'var(--radius)', padding: '10px 14px', marginBottom: 12 }}>
                <p style={{ color: 'var(--red)', fontSize: 10, letterSpacing: '0.1em', marginBottom: 4 }}>
                  ⚠ SOLO PER SCOPI DIFENSIVI — uso su sistemi non autorizzati è illegale
                </p>
              </div>
            )}

            <p style={{
              fontFamily: 'var(--font-sans)',
              fontSize: 13,
              lineHeight: 1.8,
              color: tab === 'remediation' ? 'var(--accent)' : tab === 'exploit_scenario' ? '#ffaaaa' : 'var(--text-mid)',
              whiteSpace: 'pre-wrap',
            }}>
              {tabContent[tab].text || tabContent[tab].emptyMsg}
            </p>

            {/* References solo nella tab descrizione */}
            {tab === 'description' && vuln.references?.length > 0 && (
              <div style={{ marginTop: 14 }}>
                <p style={{ fontSize: 9, letterSpacing: '0.1em', color: 'var(--text-dim)', marginBottom: 6 }}>RIFERIMENTI</p>
                {vuln.references.map((r, i) => (
                  <a key={i} href={r} target="_blank" rel="noopener noreferrer"
                    style={{ display: 'block', color: 'var(--accent)', fontSize: 11, textDecoration: 'none', fontFamily: 'var(--font-mono)', marginBottom: 2 }}>
                    → {r}
                  </a>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Shared sub-components ───────────────────────────────────────────────────

function ScoreBox({ score, riskColor, riskLabel }) {
  return (
    <div style={{ background: 'var(--bg-card)', padding: '20px 24px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minWidth: 120 }}>
      <div style={{ fontSize: 36, fontWeight: 300, color: riskColor, lineHeight: 1 }}>{score}</div>
      <div style={{ fontSize: 9, letterSpacing: '0.15em', color: riskColor, marginTop: 4 }}>{riskLabel}</div>
    </div>
  );
}

function InfoBox({ label, value, accent }) {
  return (
    <div style={{ background: 'var(--bg-card)', padding: '20px 18px' }}>
      <p style={{ fontSize: 9, letterSpacing: '0.15em', color: 'var(--text-dim)', marginBottom: 6 }}>{label}</p>
      <p style={{ fontSize: 22, fontWeight: 300, color: accent ? 'var(--orange)' : 'var(--text)' }}>{value}</p>
    </div>
  );
}

function InfoPill({ label, value, warn }) {
  return (
    <div>
      <span style={{ fontSize: 9, letterSpacing: '0.15em', color: 'var(--text-dim)' }}>{label} </span>
      <span style={{ fontSize: 12, color: warn ? 'var(--orange)' : 'var(--text)' }}>{value}</span>
    </div>
  );
}

function Section({ title, count, children }) {
  return (
    <div style={{ marginBottom: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
        <p style={{ fontSize: 10, letterSpacing: '0.15em', color: 'var(--text-dim)' }}>{title}</p>
        {count != null && <span style={{ fontSize: 9, background: 'var(--border-bright)', color: 'var(--text-mid)', padding: '1px 6px', borderRadius: 10 }}>{count}</span>}
      </div>
      {children}
    </div>
  );
}
