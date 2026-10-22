import fs from 'node:fs/promises';
import { getLlama, resolveModelFile, LlamaChatSession, LlamaLogLevel, LlamaJsonSchemaValidationError } from 'node-llama-cpp';
import { config, MODEL_PRESETS } from '../config.js';

// Motore LLM embedded: il modello GGUF gira dentro il processo Node tramite
// llama.cpp (node-llama-cpp). Nessun servizio esterno da avviare.
//
// Stati: disabled → idle (modello non scaricato) → downloading → loading → ready
//                                                         ↘ error (riprovabile)

class AiEngine {
  state = 'idle';
  error = null;
  progress = null;
  downloaded = false;
  modelPath = null;
  modelSize = null;
  llama = null;
  model = null;
  context = null;
  #loading = null;
  #abort = null;
  #queue = Promise.resolve();
  #pending = 0;

  constructor(options) {
    this.options = options;
    if (!options.enabled) this.state = 'disabled';
  }

  async init() {
    if (this.state === 'disabled') return;
    this.downloaded = await this.#isDownloaded();
    if (this.downloaded && this.options.autoload) {
      this.load().catch(() => {});
    }
  }

  async #isDownloaded() {
    const { uri, local } = this.options.model;
    try {
      if (local) { await fs.access(uri); return true; }
      await resolveModelFile(uri, { directory: this.options.modelsDir, download: false, cli: false });
      return true;
    } catch {
      return false;
    }
  }

  /** Scarica (se serve) e carica il modello. Idempotente. */
  load() {
    if (this.state === 'disabled') return Promise.reject(new Error('AI disabilitata (AI_ENABLED=false)'));
    if (this.state === 'ready') return Promise.resolve();
    this.#loading ??= this.#load().catch(err => {
      this.#loading = null;
      this.state = 'error';
      this.error = err?.name === 'AbortError' || this.#abort?.signal.aborted ? 'Download annullato' : err?.message || String(err);
      throw err;
    });
    return this.#loading;
  }

  async #load() {
    this.error = null;
    this.#abort = new AbortController();
    const { uri, local } = this.options.model;

    if (!local) {
      this.state = this.downloaded ? 'loading' : 'downloading';
      await fs.mkdir(this.options.modelsDir, { recursive: true });
      this.modelPath = await resolveModelFile(uri, {
        directory: this.options.modelsDir,
        cli: false,
        signal: this.#abort.signal,
        onProgress: ({ totalSize, downloadedSize }) => {
          this.state = 'downloading';
          this.progress = { downloaded: downloadedSize, total: totalSize };
        },
      });
    } else {
      this.modelPath = uri;
    }
    this.downloaded = true;
    this.progress = null;
    this.modelSize = (await fs.stat(this.modelPath).catch(() => null))?.size ?? null;

    this.state = 'loading';
    this.llama ??= await getLlama({ gpu: this.options.gpu, logLevel: LlamaLogLevel.error });
    this.model = await this.llama.loadModel({ modelPath: this.modelPath });
    this.context = await this.model.createContext({ contextSize: { max: this.options.contextSize } });
    this.state = 'ready';
  }

  cancel() {
    if (this.state === 'downloading') this.#abort?.abort();
  }

  status() {
    const { model } = this.options;
    return {
      enabled: this.state !== 'disabled',
      state: this.state,
      error: this.error,
      downloaded: this.downloaded,
      progress: this.progress,
      model: { label: model.label, uri: model.local ? model.label + '.gguf' : model.uri, preset: model.preset, sizeHint: model.sizeHint, size: this.modelSize },
      gpu: this.llama ? this.llama.gpu || 'cpu' : null,
      queue: this.#pending,
      presets: Object.entries(MODEL_PRESETS).map(([id, p]) => ({ id, label: p.label, sizeHint: p.sizeHint })),
    };
  }

  /**
   * Genera una risposta JSON vincolata da uno schema (grammar GBNF): il modello
   * non può produrre output malformato.
   */
  generate({ systemPrompt, prompt, schema, maxTokens = 2048, signal, onQueued, onText, onToken }) {
    if (this.state !== 'ready') return Promise.reject(new Error('Modello AI non pronto'));
    const position = this.#pending++;
    if (position > 0) onQueued?.(position);

    const run = async () => {
      signal?.throwIfAborted();
      const grammar = await this.llama.createGrammarForJsonSchema(schema);
      const sequence = this.context.getSequence();
      const session = new LlamaChatSession({ contextSequence: sequence, systemPrompt });
      try {
        const text = await session.prompt(prompt, {
          grammar,
          maxTokens,
          temperature: 0.2,
          signal,
          budgets: { thoughtTokens: 0 }, // niente ragionamento esteso: serve una risposta rapida
          onTextChunk: onText,
          onToken: tokens => onToken?.(tokens.length),
        });
        try {
          return grammar.parse(text);
        } catch (err) {
          // La grammar conta i caratteri diversamente da JS (emoji, escape): la
          // struttura resta valida, i limiti di lunghezza li riapplica il chiamante.
          if (err instanceof LlamaJsonSchemaValidationError) return JSON.parse(text);
          throw err;
        }
      } finally {
        session.dispose();
        sequence.dispose();
      }
    };

    const job = this.#queue.then(run);
    this.#queue = job.catch(() => {}).finally(() => { this.#pending--; });
    return job;
  }

  async dispose() {
    await this.context?.dispose();
    await this.model?.dispose();
    await this.llama?.dispose();
  }
}

export const engine = new AiEngine(config.ai);
