import { WEIGHTS } from '../scanner/score.js';
import { SEVERITIES } from '../scanner/checks.js';

// Analista integrato: produce sommario, scenari d'attacco e priorità a partire
// dai finding deterministici, con testi scritti a mano e contestualizzati sui
// dati della scansione. Nessun modello da scaricare, risposta istantanea.
// Se il modello AI opzionale è pronto viene usato quello (vedi routes/api.js).

export const BUILTIN_MODEL = 'Analista integrato';

function context(report) {
  const host = new URL(report.finalUrl).host;
  const stacks = report.tech?.stacks ?? [];
  return {
    report,
    host,
    onion: report.isOnion,
    on: stacks.length ? ` su ${stacks.join(' e ')}` : '',
  };
}

// minuscola iniziale, ma non sulle sigle ("TLS 1.3", "HSTS configurato")
const lcFirst = s => /^[A-Z][A-Z0-9]/.test(s) ? s : s.charAt(0).toLowerCase() + s.slice(1);

// "il cookie X" / "i cookie X, Y" con l'accordo del verbo che segue.
function cookies(f) {
  if (!f.evidence) return { the: 'questi cookie', many: true };
  const many = /,| e altri /.test(f.evidence);
  return { the: `${many ? 'i' : 'il'} cookie ${f.evidence}`, many };
}
const ONION_DISCLOSURE = ' Su un servizio .onion queste informazioni aiutano anche a collegare il server ad altri siti e a deanonimizzarlo.';

// ─── Scenari d'attacco (concettuali, senza payload) ──────────────────────────

const SCENARIOS = {
  'git-exposed': c =>
    `Chiunque può scaricare la cartella .git di ${c.host} e ricostruire con strumenti automatici il codice sorgente completo, cronologia compresa. Password, chiavi API e configurazioni finite nei commit diventano accessibili senza bisogno di altre vulnerabilità.`,
  'env-exposed': c =>
    `I bot che scansionano Internet cercano proprio /.env: su ${c.host} lo troverebbero e ne leggerebbero il contenuto in pochi secondi. Con le credenziali del database o le chiavi API contenute, l'attaccante accede direttamente ai dati o ai servizi collegati.`,
  'no-https': c =>
    `Su una rete Wi-Fi pubblica, chi controlla il router o si trova sulla stessa rete può leggere e modificare tutto il traffico verso ${c.host}: password, cookie di sessione e contenuto delle pagine. Può anche iniettare script o link malevoli nelle pagine servite.`,
  'http-no-redirect': c =>
    `Chi digita ${c.host} senza https:// apre la versione in chiaro: un attaccante sulla stessa rete può intercettare quella richiesta e tenere la vittima su HTTP (SSL stripping). Da lì legge credenziali e cookie anche se il sito supporta HTTPS.`,
  'tls-expired': c =>
    `I visitatori di ${c.host} vedono un avviso di sicurezza bloccante e chi lo ignora si abitua a "proseguire comunque". Un attaccante sulla rete può allora presentare un certificato falso senza che l'utente noti la differenza.`,
  'tls-invalid': c =>
    `Poiché il certificato di ${c.host} non è verificabile, un attaccante sulla rete può sostituirlo con uno suo (man-in-the-middle) e il browser mostrerebbe lo stesso avviso che gli utenti vedono già. La connessione resta cifrata, ma senza garanzia di parlare con il server giusto.`,
  'tls-expiring': c =>
    `Se il rinnovo automatico non parte, tra ${c.report.tls?.daysLeft ?? 'pochi'} giorni ${c.host} mostrerà un errore bloccante a utenti e servizi che lo chiamano. Non è un attacco, ma un'interruzione del servizio facilmente evitabile.`,
  'tls-old-protocol': c =>
    `Con ${c.report.tls?.protocol ?? 'un protocollo obsoleto'} un attaccante in posizione man-in-the-middle può sfruttare debolezze crittografiche note del protocollo. Inoltre i browser moderni rifiutano queste connessioni, quindi parte degli utenti non raggiunge il sito.`,
  'tls-weak-key': c =>
    `Una chiave RSA sotto i 2048 bit è alla portata di attaccanti con risorse di calcolo significative, che potrebbero ricavarne la chiave privata. Con essa potrebbero impersonare ${c.host} o decifrare traffico registrato in precedenza.`,
  'tls-error': c =>
    `L'analisi separata del certificato di ${c.host} non è riuscita, quindi eventuali problemi TLS non sono stati valutati. Verifica la configurazione con un servizio come SSL Labs prima di considerarla sicura.`,
  'hsts-missing': c =>
    `Un utente che arriva su ${c.host} da un link http:// o da un vecchio segnalibro passa per una connessione in chiaro prima del redirect. Un attaccante sulla stessa rete può intercettarla e servire una versione HTTP del sito per rubare le credenziali.`,
  'hsts-weak': c =>
    `Con un max-age breve la protezione HSTS scade presto: un utente che torna su ${c.host} dopo qualche tempo è di nuovo esposto allo SSL stripping alla prima richiesta.`,
  'csp-missing': c =>
    `Se in ${c.host} esiste anche una sola falla XSS (un campo di ricerca o un commento non filtrato), il browser eseguirà lo script iniettato senza alcun freno. L'attaccante può così rubare la sessione, leggere i dati mostrati nella pagina o agire a nome dell'utente.`,
  'csp-unsafe-inline': c =>
    `La policy di ${c.host} consente gli script inline, cioè proprio il tipo di codice che un attacco XSS inietta nella pagina. In caso di XSS la CSP non blocca nulla e l'attaccante può rubare sessioni o modificare i contenuti.`,
  'csp-unsafe-eval': c =>
    `Con 'unsafe-eval' una stringa controllata dall'attaccante che arriva a eval() o funzioni simili su ${c.host} viene eseguita come codice. Questo rende sfruttabili XSS basati sul DOM che una policy più stretta bloccherebbe.`,
  'csp-wildcard': c =>
    `Le sorgenti troppo ampie permettono di caricare script da domini controllati dall'attaccante o da CDN pubbliche con librerie vulnerabili. In caso di HTML injection su ${c.host} basta includere uno di questi script per aggirare la policy.`,
  'clickjacking': c =>
    `Un sito malevolo può caricare ${c.host} in un iframe invisibile e sovrapporgli un pulsante esca, ad esempio "Vinci un premio". L'utente, già autenticato, in realtà clicca su un'azione del tuo sito: una conferma, un cambio di impostazioni, un acquisto.`,
  'nosniff-missing': c =>
    `Se ${c.host} serve file caricati dagli utenti, un attaccante può caricarne uno che il browser "indovina" come HTML o script invece che come testo. Un upload apparentemente innocuo diventa così un attacco XSS.`,
  'referrer-policy-missing': c =>
    `Senza una policy esplicita il comportamento dipende dal browser e quelli più datati inviano l'URL completo delle pagine di ${c.host} ai siti esterni linkati. Token o dati personali presenti negli URL possono così finire nei log di terzi.`,
  'referrer-policy-weak': c =>
    `Con la policy attuale l'URL completo delle pagine di ${c.host}, parametri compresi, viene inviato a ogni sito esterno linkato o incorporato. Link di reset password o identificativi negli URL finiscono così nei log di terzi.`,
  'permissions-policy-missing': c =>
    `Uno script di terze parti o un iframe compromesso incluso in ${c.host} potrebbe chiedere l'accesso a fotocamera, microfono o posizione con il nome del tuo sito. Una Permissions-Policy limita queste API alle sole funzioni che usi davvero.`,
  'xxss-legacy': () =>
    `Il vecchio filtro XSS dei browser è stato rimosso perché poteva essere sfruttato per far trapelare informazioni dalla pagina. Mantenerlo attivo non protegge più nulla e su browser datati può introdurre comportamenti indesiderati.`,
  'server-version': (c, f) =>
    `Un attaccante legge ${f.evidence || 'la versione del server'} e in pochi secondi trova le CVE note per quella release. Se il server non è aggiornato passa direttamente a un exploit mirato, senza scansioni rumorose.` + (c.onion ? ONION_DISCLOSURE : ''),
  'powered-by': (c, f) =>
    `${f.evidence || 'X-Powered-By'} rivela la tecnologia del backend di ${c.host}, così un attaccante sceglie subito gli attacchi specifici per quel framework. Non è una vulnerabilità di per sé, ma riduce il lavoro di ricognizione.` + (c.onion ? ONION_DISCLOSURE : ''),
  'aspnet-version': (c, f) =>
    `La versione esatta del runtime (${f.evidence || 'ASP.NET'}) permette di cercare vulnerabilità note specifiche per quella release. Su un server non aggiornato accorcia la strada verso un exploit mirato.` + (c.onion ? ONION_DISCLOSURE : ''),
  'generator-version': (c, f) =>
    `I bot cercano in massa i siti che dichiarano ${f.evidence || 'il proprio CMS'}: se esiste una vulnerabilità nota per quella versione o per i suoi plugin, ${c.host} finisce automaticamente tra i bersagli. Gli attacchi ai CMS sono quasi sempre automatizzati e partono proprio da questa informazione.` + (c.onion ? ONION_DISCLOSURE : ''),
  'cookie-insecure': (c, f) => {
    const k = cookies(f);
    return `Se un utente apre anche una sola volta una pagina http:// di ${c.host}, il browser invia in chiaro ${k.the}. Un attaccante sulla stessa rete ${k.many ? 'li intercetta e, se sono cookie' : 'lo intercetta e, se è un cookie'} di sessione, entra nell'account dell'utente.`;
  },
  'cookie-no-httponly': (c, f) => {
    const k = cookies(f);
    return `In caso di XSS su ${c.host}, lo script iniettato può leggere ${k.the} e ${k.many ? 'inviarli' : 'inviarlo'} a un server dell'attaccante. Se ${k.many ? 'sono cookie' : 'è un cookie'} di sessione, l'attaccante può impersonare l'utente.`;
  },
  'cookie-no-samesite': (c, f) => {
    const k = cookies(f);
    return `Senza SameSite esplicito, ${k.the} ${k.many ? 'possono essere inviati' : 'può essere inviato'} anche in richieste partite da altri siti, a seconda del browser. Un sito malevolo potrebbe così far compiere all'utente autenticato azioni su ${c.host} (CSRF).`;
  },
  'cors-reflect-credentials': c =>
    `Un utente autenticato visita il sito dell'attaccante, che via JavaScript chiede dati a ${c.host} e ne legge le risposte, perché il server accetta qualsiasi origine e include i cookie. In pratica qualunque sito può leggere i dati privati dei tuoi utenti.`,
  'cors-reflect': c =>
    `Qualsiasi sito può leggere via JavaScript le risposte di ${c.host} dal browser dei visitatori. Se le risposte dipendono dalla rete dell'utente (intranet, IP autorizzati) o contengono dati non pubblici, questi vengono esposti a terzi.`,
  'cors-wildcard': c =>
    `Qualsiasi sito può leggere le risposte non autenticate di ${c.host}. È accettabile per API e contenuti pubblici, ma diventa una fuga di dati se una di quelle risposte contiene informazioni riservate.`,
  'security-txt-missing': c =>
    `Chi scopre una vulnerabilità su ${c.host} non sa a chi segnalarla e potrebbe rinunciare o pubblicarla. Un contatto dichiarato aumenta le probabilità di essere avvisati prima di un attaccante.`,
};

// ─── Priorità ────────────────────────────────────────────────────────────────

const HEADER_NAMES = {
  'hsts-missing': 'HSTS',
  'csp-missing': 'una Content-Security-Policy',
  'clickjacking': 'la protezione da clickjacking (frame-ancestors)',
  'nosniff-missing': 'X-Content-Type-Options: nosniff',
  'referrer-policy-missing': 'Referrer-Policy',
};

const joinList = items => items.length <= 1 ? items.join('') : `${items.slice(0, -1).join(', ')} e ${items.at(-1)}`;
const cookieNames = findings => joinList([...new Set(findings.flatMap(f => (f.evidence || '').split(/,\s*| e altri \d+/).filter(Boolean)))].slice(0, 4));

// Ogni gruppo raccoglie finding che si correggono con lo stesso intervento.
// effort: 1 = una riga di configurazione, 3 = lavoro più impegnativo.
const ACTIONS = [
  {
    ids: ['env-exposed', 'git-exposed'], effort: 1,
    text: (c, fs) => {
      const has = id => fs.some(f => f.id === id);
      const paths = joinList([has('git-exposed') && '/.git', has('env-exposed') && '/.env'].filter(Boolean));
      const both = fs.length > 1;
      return `Blocca subito l'accesso pubblico a ${paths}${c.on}, ${both ? 'togli quei file' : 'togli il file'} dalla document root e considera compromesse le credenziali che ${both ? 'contenevano' : 'conteneva'}: ruotale tutte.`;
    },
  },
  { ids: ['no-https'], effort: 3, text: c => `Attiva HTTPS su ${c.host} con un certificato gratuito Let's Encrypt e reindirizza tutto il traffico HTTP.` },
  { ids: ['tls-expired'], effort: 1, text: () => 'Rinnova subito il certificato TLS e verifica che il rinnovo automatico funzioni.' },
  { ids: ['tls-invalid'], effort: 2, text: c => `Installa un certificato emesso da una CA riconosciuta (ad esempio Let's Encrypt) e valido per ${c.host}.` },
  { ids: ['tls-old-protocol'], effort: 2, text: () => 'Disabilita TLS 1.0 e 1.1 e lascia attivi solo TLS 1.2 e TLS 1.3.' },
  { ids: ['cors-reflect-credentials', 'cors-reflect'], effort: 2, text: () => 'Limita CORS a un elenco esplicito di origini fidate invece di rispecchiare l\'header Origin ricevuto.' },
  { ids: ['http-no-redirect'], effort: 1, text: c => `Reindirizza tutte le richieste HTTP su HTTPS con un redirect 301${c.on}.` },
  {
    ids: ['cookie-insecure', 'cookie-no-httponly', 'cookie-no-samesite'], effort: 2,
    text: (c, fs) => `Imposta Secure, HttpOnly e SameSite=Lax sui cookie${fs.some(f => f.evidence) ? ` (${cookieNames(fs)})` : ''}, lasciando senza HttpOnly solo quelli che il JavaScript deve davvero leggere.`,
  },
  {
    ids: Object.keys(HEADER_NAMES), effort: 1,
    text: (c, fs) => `Aggiungi gli header di sicurezza mancanti${c.on}: ${joinList(fs.map(f => HEADER_NAMES[f.id]))}.`,
  },
  {
    ids: ['csp-unsafe-inline', 'csp-unsafe-eval', 'csp-wildcard'], effort: 3,
    text: () => 'Rendi più restrittiva la Content-Security-Policy: elimina \'unsafe-inline\', \'unsafe-eval\' e le sorgenti jolly, usando nonce o hash per gli script necessari.',
  },
  { ids: ['tls-expiring'], effort: 1, text: c => `Verifica il rinnovo automatico del certificato prima della scadenza tra ${c.report.tls?.daysLeft ?? 'pochi'} giorni.` },
  { ids: ['tls-weak-key'], effort: 2, text: () => 'Rigenera il certificato con una chiave RSA da almeno 2048 bit oppure ECDSA.' },
  { ids: ['tls-error'], effort: 1, text: c => `Controlla la configurazione TLS di ${c.host} con SSL Labs, perché la verifica automatica non è riuscita.` },
  { ids: ['hsts-weak'], effort: 1, text: () => 'Porta il max-age di HSTS ad almeno un anno (31536000 secondi).' },
  { ids: ['referrer-policy-weak'], effort: 1, text: () => 'Imposta Referrer-Policy a strict-origin-when-cross-origin.' },
  {
    ids: ['server-version', 'powered-by', 'aspnet-version', 'generator-version'], effort: 1,
    text: (c, fs) => `Nascondi versione e tecnologia esposte negli header${fs.some(f => f.id === 'generator-version') ? ' e nel tag generator' : ''}${c.on}${fs.some(f => f.id === 'generator-version') ? ', e aggiorna il CMS all\'ultima versione' : ''}.`,
  },
  { ids: ['permissions-policy-missing'], effort: 1, text: () => 'Aggiungi una Permissions-Policy che disattivi le API del browser che non usi (fotocamera, microfono, geolocalizzazione).' },
  { ids: ['xxss-legacy'], effort: 1, text: () => 'Imposta X-XSS-Protection a 0 e affida la protezione da XSS alla Content-Security-Policy.' },
  { ids: ['security-txt-missing'], effort: 1, text: () => 'Pubblica /.well-known/security.txt con un indirizzo per le segnalazioni di sicurezza.' },
  { ids: ['cors-wildcard'], effort: 1, text: () => 'Verifica che le risposte servite con Access-Control-Allow-Origin: * non contengano dati riservati.' },
];

const MAX_PRIORITIES = 5;

function priorities(c, findings) {
  const rank = f => SEVERITIES.indexOf(f.severity);
  const actions = ACTIONS
    .map((a, order) => {
      const fs = findings.filter(f => a.ids.includes(f.id));
      if (!fs.length) return null;
      return {
        order,
        top: Math.min(...fs.map(rank)),
        value: fs.reduce((s, f) => s + WEIGHTS[f.severity], 0) / a.effort,
        text: a.text(c, fs),
      };
    })
    .filter(Boolean)
    // prima la gravità del problema peggiore, poi il rapporto impatto/sforzo
    .sort((a, b) => a.top - b.top || b.value - a.value || a.order - b.order);

  const important = actions.filter(a => a.value > 0);
  const extra = actions.filter(a => a.value === 0);
  return [...important, ...extra.slice(0, Math.max(0, 3 - important.length))]
    .slice(0, MAX_PRIORITIES)
    .map(a => a.text);
}

// ─── Sommario ────────────────────────────────────────────────────────────────

const COUNT_WORDS = [
  ['critical', 'critico', 'critici'], ['high', 'grave', 'gravi'],
  ['medium', 'medio', 'medi'], ['low', 'minore', 'minori'],
];

const RISK_SENTENCE = {
  critical: 'Con un problema critico il sito è esposto ad attacchi automatizzati: va corretto prima di qualsiasi altra cosa.',
  high: 'Sono problemi sfruttabili da un attaccante sulla rete o tramite un altro sito: conviene correggerli a breve.',
  medium: 'Nessun problema critico o grave, ma mancano difese importanti che limitano i danni in caso di attacco, ad esempio una XSS.',
  low: 'La postura è buona: restano soprattutto ritocchi di configurazione e informazioni esposte.',
  none: 'Restano solo suggerimenti di buona pratica.',
};

function summary(c, report) {
  const { findings, counts, positives } = report;
  const real = findings.filter(f => f.severity !== 'info');
  const good = positives.slice(0, 2).map(p => lcFirst(p.title));

  if (!real.length) {
    return `${c.host} supera tutti i controlli automatici (${report.score}/100, voto ${report.grade})${good.length ? `, con ${joinList(good)}` : ''}. ` +
      (counts.info ? `${RISK_SENTENCE.none} ` : '') +
      'Ripeti la scansione dopo ogni modifica alla configurazione del server.';
  }

  const parts = COUNT_WORDS.filter(([s]) => counts[s]).map(([s, one, many]) => `${counts[s]} ${counts[s] === 1 ? one : many}`);
  const info = counts.info ? ` (più ${counts.info} ${counts.info === 1 ? 'suggerimento' : 'suggerimenti'})` : '';
  const top = real.slice(0, 2).map(f => `«${f.title}»`);
  const sentences = [
    `${c.host} ottiene ${report.score}/100 (voto ${report.grade}) con ${real.length} ${real.length === 1 ? 'problema' : 'problemi'}: ${joinList(parts)}${info}.`,
    `${top.length > 1 ? 'I più urgenti sono' : 'Il più urgente è'} ${joinList(top)}.`,
    RISK_SENTENCE[report.riskLevel] ?? RISK_SENTENCE.low,
  ];
  if (good.length) sentences.push(`Configurati bene: ${joinList(good)}.`);
  if (c.onion && findings.some(f => f.category === 'Information disclosure')) {
    sentences.push('Trattandosi di un servizio .onion, elimina per prime le informazioni che possono rivelare il server reale.');
  }
  return sentences.join(' ');
}

// ─── Entry point ─────────────────────────────────────────────────────────────

export function explainBuiltin(report) {
  const started = Date.now();
  const c = context(report);
  const scenarios = {};
  for (const f of report.findings) {
    if (f.severity !== 'info' && SCENARIOS[f.id]) scenarios[f.id] = SCENARIOS[f.id](c, f);
  }
  return {
    model: BUILTIN_MODEL,
    engine: 'builtin',
    summary: summary(c, report),
    scenarios,
    priorities: priorities(c, report.findings),
    tokens: 0,
    durationMs: Date.now() - started,
  };
}

export { SCENARIOS as _SCENARIOS, ACTIONS as _ACTIONS };
