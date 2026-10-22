import { SEVERITY, RISK, formatDate, hostOf } from './format.js';

export function download(filename, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = Object.assign(document.createElement('a'), { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

const slug = report => `vulnscan-${hostOf(report.finalUrl).replace(/[^a-z0-9.-]/gi, '_')}-${report.scannedAt.slice(0, 10)}`;

export function exportJson(report) {
  download(`${slug(report)}.json`, JSON.stringify(report, null, 2), 'application/json');
}

export function toMarkdown(report) {
  const lines = [
    `# Report di sicurezza — ${hostOf(report.finalUrl)}`,
    '',
    `- **URL:** ${report.finalUrl}`,
    `- **Data:** ${formatDate(report.scannedAt)}`,
    `- **Punteggio:** ${report.score}/100 (voto ${report.grade}) — ${RISK[report.riskLevel]}`,
    `- **Problemi:** ${Object.entries(report.counts).filter(([, n]) => n).map(([s, n]) => `${n} ${SEVERITY[s].label.toLowerCase()}`).join(', ') || 'nessuno'}`,
    '',
  ];
  if (report.ai) {
    lines.push(`## Analisi (${report.ai.model})`, '', report.ai.summary, '');
    if (report.ai.priorities.length) {
      lines.push('### Priorità', '', ...report.ai.priorities.map((p, i) => `${i + 1}. ${p}`), '');
    }
  }
  lines.push('## Problemi rilevati', '');
  if (!report.findings.length) lines.push('Nessun problema rilevato.', '');
  for (const f of report.findings) {
    lines.push(`### [${SEVERITY[f.severity].label}] ${f.title}`, '', `*${f.category}*`, '', f.description, '');
    if (f.evidence) lines.push(`**Evidenza:** \`${f.evidence}\``, '');
    const scenario = report.ai?.scenarios?.[f.id];
    if (scenario) lines.push(`**Scenario d'attacco${report.ai.engine === 'builtin' ? '' : ' (AI)'}:** ${scenario}`, '');
    for (const s of f.remediation) lines.push(`**Correzione — ${s.label}:**`, '', '```', s.code, '```', '');
    if (f.references.length) lines.push(...f.references.map(r => `- [${r.label}](${r.url})`), '');
  }
  if (report.positives.length) {
    lines.push('## Elementi positivi', '', ...report.positives.map(p => `- **${p.title}** — ${p.description}`), '');
  }
  lines.push('## Header di sicurezza', '', '| Header | Stato | Valore |', '|---|---|---|');
  for (const h of report.headers) lines.push(`| ${h.name} | ${h.status} | ${(h.value || '—').replace(/\|/g, '\\|')} |`);
  lines.push('', '---', '_Generato da VulnScan AI — usare solo su sistemi propri o con autorizzazione._');
  return lines.join('\n');
}

export function exportMarkdown(report) {
  download(`${slug(report)}.md`, toMarkdown(report), 'text/markdown');
}
