import { useState, useEffect } from 'react';

const STEPS = [
  'Raggiungibilità target...',
  'Raccolta header HTTP...',
  'Analisi configurazione SSL...',
  'Rilevamento tecnologie esposte...',
  'Avvio analisi AI...',
  'Elaborazione vulnerabilità...',
  'Generazione report...',
];

export default function ScanLoader() {
  const [stepIdx, setStepIdx] = useState(0);
  const [dots, setDots] = useState('');

  useEffect(() => {
    const interval = setInterval(() => {
      setStepIdx(i => (i + 1) % STEPS.length);
    }, 1400);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const d = setInterval(() => setDots(p => p.length >= 3 ? '' : p + '.'), 400);
    return () => clearInterval(d);
  }, []);

  return (
    <div style={{ paddingTop: 100, textAlign: 'center', animation: 'fadeIn 0.4s ease' }}>
      {/* Spinner */}
      <div style={{ margin: '0 auto 40px', width: 60, height: 60, position: 'relative' }}>
        <div style={{
          width: '100%', height: '100%', border: '1px solid var(--border-bright)',
          borderTopColor: 'var(--accent)', borderRadius: '50%',
          animation: 'spin 0.8s linear infinite',
        }} />
        <span style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', color: 'var(--accent)', fontSize: 16 }}>⬡</span>
      </div>

      <p style={{ color: 'var(--accent)', fontSize: 13, letterSpacing: '0.15em', marginBottom: 8 }}>
        SCANSIONE IN CORSO
      </p>
      <p style={{ color: 'var(--text-mid)', fontSize: 12, fontFamily: 'var(--font-sans)', minHeight: 20 }}>
        {STEPS[stepIdx]}{dots}
      </p>

      {/* Progress lines */}
      <div style={{ marginTop: 48, maxWidth: 340, margin: '48px auto 0', textAlign: 'left' }}>
        {STEPS.slice(0, stepIdx + 1).map((s, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6, animation: 'fadeIn 0.3s ease' }}>
            <span style={{ color: i < stepIdx ? 'var(--accent)' : 'var(--text-dim)', fontSize: 10 }}>
              {i < stepIdx ? '✓' : '›'}
            </span>
            <span style={{ color: i < stepIdx ? 'var(--text-mid)' : 'var(--text)', fontSize: 11, fontFamily: 'var(--font-mono)' }}>{s}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
