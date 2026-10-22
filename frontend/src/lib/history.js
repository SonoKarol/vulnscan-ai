import { hostOf } from './format.js';

// Storico locale delle scansioni (solo nel browser dell'utente).
const KEY = 'vulnscan:history';
const MAX = 20;

export function loadHistory() {
  try {
    const list = JSON.parse(localStorage.getItem(KEY) || '[]');
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

function persist(list) {
  try {
    localStorage.setItem(KEY, JSON.stringify(list));
  } catch {
    // quota piena: tieni solo le scansioni più recenti
    try { localStorage.setItem(KEY, JSON.stringify(list.slice(0, 5))); } catch {}
  }
  return list;
}

export function saveReport(list, report) {
  return persist([report, ...list.filter(r => r.id !== report.id)].slice(0, MAX));
}

export function removeReport(list, id) {
  return persist(list.filter(r => r.id !== id));
}

export function clearHistory() {
  return persist([]);
}

/** Scansione precedente dello stesso host, per mostrare il trend del punteggio. */
export function previousScan(list, report) {
  const host = hostOf(report.finalUrl);
  return list.find(r => r.id !== report.id && hostOf(r.finalUrl) === host && r.scannedAt < report.scannedAt) ?? null;
}
