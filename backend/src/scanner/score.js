import { SEVERITIES } from './checks.js';

// Punteggio deterministico: stesso sito, stesso voto — indipendente dal modello AI.
const WEIGHTS = { critical: 35, high: 20, medium: 10, low: 4, info: 0 };

export function score(findings) {
  const counts = Object.fromEntries(SEVERITIES.map(s => [s, 0]));
  for (const f of findings) counts[f.severity]++;
  const penalty = findings.reduce((sum, f) => sum + WEIGHTS[f.severity], 0);
  const value = Math.max(0, 100 - penalty);
  const grade = value >= 90 ? 'A' : value >= 75 ? 'B' : value >= 60 ? 'C' : value >= 40 ? 'D' : 'F';
  const riskLevel = SEVERITIES.slice(0, 4).find(s => counts[s] > 0) ?? 'none';
  return { score: value, grade, riskLevel, counts };
}
