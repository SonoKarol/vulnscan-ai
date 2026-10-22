import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Carica backend/.env se presente (API nativa di Node, niente dotenv).
try { process.loadEnvFile(path.join(ROOT, '.env')); } catch {}

const env = process.env;

function bool(value, fallback) {
  if (value == null || value === '') return fallback;
  return !['0', 'false', 'no', 'off'].includes(String(value).toLowerCase());
}

// Modelli consigliati da node-llama-cpp, scelti per qualità dell'italiano e
// aderenza all'output strutturato.
export const MODEL_PRESETS = {
  leggero: {
    label: 'Qwen 3.5 0.8B',
    uri: 'hf:unsloth/Qwen3.5-0.8B-GGUF:Q8_0',
    sizeHint: '~1 GB',
  },
  bilanciato: {
    label: 'Qwen 3.5 4B',
    uri: 'hf:unsloth/Qwen3.5-4B-GGUF:Q4_K_M',
    sizeHint: '~3 GB',
  },
  accurato: {
    label: 'Qwen 3.5 9B',
    uri: 'hf:unsloth/Qwen3.5-9B-GGUF:Q4_K_M',
    sizeHint: '~6 GB',
  },
};

function resolveModel(value) {
  const key = (value || 'bilanciato').trim();
  if (MODEL_PRESETS[key]) return { preset: key, ...MODEL_PRESETS[key] };
  if (key.startsWith('hf:') || /^https?:\/\//.test(key)) {
    return { preset: null, label: key.replace(/^hf:/, '').split('/').slice(-1)[0], uri: key, sizeHint: null };
  }
  // percorso locale a un file .gguf
  const file = path.resolve(ROOT, key);
  return { preset: null, label: path.basename(file, '.gguf'), uri: file, sizeHint: null, local: true };
}

function gpuOption(value) {
  const v = (value || 'auto').toLowerCase();
  if (['false', 'cpu', 'off', 'none'].includes(v)) return false;
  if (['cuda', 'vulkan', 'metal'].includes(v)) return v;
  return 'auto';
}

// socks5:// risolve i nomi in locale, ma i .onion esistono solo dentro Tor.
function torProxy(value) {
  return (value || 'socks5h://127.0.0.1:9150').replace(/^socks5:\/\//i, 'socks5h://');
}

export const config = {
  root: ROOT,
  version: '2.0.0',
  port: Number(env.PORT) || 3001,
  host: env.HOST || '127.0.0.1',
  torProxy: torProxy(env.TOR_PROXY),
  allowPrivateTargets: bool(env.ALLOW_PRIVATE_TARGETS, false),
  ai: {
    enabled: bool(env.AI_ENABLED, true),
    model: resolveModel(env.AI_MODEL),
    modelsDir: path.resolve(ROOT, env.AI_MODELS_DIR || './models'),
    autoload: bool(env.AI_AUTOLOAD, true),
    gpu: gpuOption(env.AI_GPU),
    contextSize: Number(env.AI_CONTEXT_SIZE) || 8192,
  },
};
