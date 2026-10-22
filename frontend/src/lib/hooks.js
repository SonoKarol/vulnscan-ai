import { useCallback, useEffect, useReducer, useRef, useState } from 'react';
import { getStatus, getTor, streamScan } from './api.js';

// ─── Stato del motore AI (polling adattivo) ──────────────────────────────────

export function useEngineStatus() {
  const [status, setStatus] = useState(null);
  const [offline, setOffline] = useState(false);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let alive = true;
    let timer;
    const tick = async () => {
      let next = 10_000;
      try {
        const s = await getStatus();
        if (!alive) return;
        setStatus(s.ai);
        setOffline(false);
        if (['downloading', 'loading'].includes(s.ai.state)) next = 800;
      } catch {
        if (!alive) return;
        setOffline(true);
        next = 3000;
      }
      timer = setTimeout(tick, next);
    };
    tick();
    return () => { alive = false; clearTimeout(timer); };
  }, [nonce]);

  const refresh = useCallback(() => setNonce(n => n + 1), []);
  return { status, offline, refresh };
}

// ─── Tor (verificato solo quando serve) ──────────────────────────────────────

export function useTor(active) {
  const [tor, setTor] = useState('unknown');
  const check = useCallback(async (refresh = false) => {
    setTor('checking');
    try { setTor((await getTor(refresh)).tor); } catch { setTor('offline'); }
  }, []);
  useEffect(() => { if (active && tor === 'unknown') check(); }, [active, tor, check]);
  return { tor, check };
}

// ─── Tema ────────────────────────────────────────────────────────────────────

const THEMES = ['system', 'dark', 'light'];

export function useTheme() {
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem('vulnscan:theme') || 'system'; } catch { return 'system'; }
  });
  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'system') delete root.dataset.theme;
    else root.dataset.theme = theme;
    try { localStorage.setItem('vulnscan:theme', theme); } catch {}
  }, [theme]);
  const cycle = () => setTheme(t => THEMES[(THEMES.indexOf(t) + 1) % THEMES.length]);
  return { theme, cycle };
}

// ─── Scansione in streaming ──────────────────────────────────────────────────

const initial = {
  phase: 'idle', target: null, wantAi: true, steps: {}, report: null,
  aiProgress: null, aiError: null, queued: 0, error: null, fromHistory: false,
};

function reducer(state, e) {
  switch (e.type) {
    case 'start':
      return { ...initial, phase: 'running', target: e.url, wantAi: e.ai };
    case 'open':
      return { ...initial, phase: 'done', target: e.report.target, report: e.report, fromHistory: true };
    case 'reset':
      return initial;
    case 'step':
      return { ...state, steps: { ...state.steps, [e.id]: { status: e.status, detail: e.detail } } };
    case 'report':
      return { ...state, report: e.report };
    case 'ai-queued':
      return { ...state, queued: e.position };
    case 'ai-progress':
      return { ...state, queued: 0, aiProgress: { tokens: e.tokens, summary: e.summary ?? state.aiProgress?.summary ?? '' } };
    case 'ai':
      return { ...state, report: { ...state.report, ai: e.ai } };
    case 'ai-error':
      return { ...state, aiError: e.message };
    case 'error':
      return { ...state, phase: 'error', error: { message: e.message, details: e.details ?? [] } };
    case 'done':
      return state.phase === 'running' ? { ...state, phase: 'done' } : state;
    default:
      return state;
  }
}

export function useScan() {
  const [state, dispatch] = useReducer(reducer, initial);
  const controller = useRef(null);

  const start = useCallback(async (url, { ai }) => {
    controller.current?.abort();
    const ctrl = new AbortController();
    controller.current = ctrl;
    dispatch({ type: 'start', url, ai });
    let finished = false;
    try {
      await streamScan(url, {
        ai,
        signal: ctrl.signal,
        onEvent: event => {
          if (event.type === 'done' || event.type === 'error') finished = true;
          dispatch(event);
        },
      });
      if (!finished) dispatch({ type: 'error', message: 'Connessione con il backend interrotta' });
    } catch (err) {
      if (ctrl.signal.aborted) return;
      dispatch({ type: 'error', message: err.message === 'Failed to fetch' ? 'Backend non raggiungibile — è avviato?' : err.message });
    }
  }, []);

  const reset = useCallback(() => {
    controller.current?.abort();
    dispatch({ type: 'reset' });
  }, []);

  const open = useCallback(report => {
    controller.current?.abort();
    dispatch({ type: 'open', report });
  }, []);

  useEffect(() => () => controller.current?.abort(), []);

  return { state, start, reset, open };
}
