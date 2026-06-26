import { useState } from 'react';
import ScanForm from './components/ScanForm';
import ScanReport from './components/ScanReport';
import ScanLoader from './components/ScanLoader';

export default function App() {
  const [state, setState] = useState('idle'); // idle | loading | result | error
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);

  async function handleScan(url) {
    setState('loading');
    setError(null);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Errore durante la scansione');
      setReport(data);
      setState('result');
    } catch (err) {
      setError(err.message);
      setState('error');
    }
  }

  function handleReset() {
    setState('idle');
    setReport(null);
    setError(null);
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Header />
      <main style={{ flex: 1, padding: '0 24px 48px', maxWidth: 900, margin: '0 auto', width: '100%' }}>
        {(state === 'idle' || state === 'error') && (
          <ScanForm onScan={handleScan} error={error} />
        )}
        {state === 'loading' && <ScanLoader />}
        {state === 'result' && report && (
          <ScanReport report={report} onReset={handleReset} />
        )}
      </main>
      <Footer />
    </div>
  );
}

function Header() {
  return (
    <header style={{ borderBottom: '1px solid var(--border)', padding: '20px 24px', display: 'flex', alignItems: 'center', gap: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ color: 'var(--accent)', fontSize: 20 }}>⬡</span>
        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, letterSpacing: '0.08em', fontSize: 15 }}>
          VULNSCAN<span style={{ color: 'var(--accent)' }}>AI</span>
        </span>
      </div>
      <div style={{ flex: 1 }} />
      <span style={{ color: 'var(--text-dim)', fontSize: 11, letterSpacing: '0.1em' }}>
        v1.0.0 — USE RESPONSIBLY
      </span>
    </header>
  );
}

function Footer() {
  return (
    <footer style={{ borderTop: '1px solid var(--border)', padding: '16px 24px', textAlign: 'center', color: 'var(--text-dim)', fontSize: 11, letterSpacing: '0.05em' }}>
      ⚠ Solo per uso su sistemi di tua proprietà o con permesso esplicito. Scansionare siti di terzi senza consenso è illegale.
    </footer>
  );
}
