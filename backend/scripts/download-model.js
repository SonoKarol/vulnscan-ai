// Scarica e verifica il modello configurato in AI_MODEL senza avviare il server.
//   npm run model:download            → modello da .env
//   npm run model:download accurato   → preset specifico
import { resolveModelFile } from 'node-llama-cpp';
import { config, MODEL_PRESETS } from '../src/config.js';

const arg = process.argv[2];
const model = arg && MODEL_PRESETS[arg] ? { ...MODEL_PRESETS[arg] } : config.ai.model;

if (model.local) {
  console.log(`Il modello è un file locale: ${model.uri}`);
  process.exit(0);
}

console.log(`⬇  ${model.label}${model.sizeHint ? ` (${model.sizeHint})` : ''}\n   ${model.uri}\n   → ${config.ai.modelsDir}\n`);
const file = await resolveModelFile(model.uri, { directory: config.ai.modelsDir, cli: true });
console.log(`\n✅ Modello pronto: ${file}`);
if (arg && MODEL_PRESETS[arg]) console.log(`   Imposta AI_MODEL=${arg} in backend/.env per usarlo.`);
