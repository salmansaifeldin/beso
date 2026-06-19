#!/usr/bin/env node
/*
 * Build a human-readable report from repo-results.jsonl.
 * Usage: node report.js [repo-results.jsonl] [report.md]
 */
const fs = require('fs');
const IN = process.argv[2] || 'repo-results.jsonl';
const OUT = process.argv[3] || 'report.md';

const rows = [];
for (const line of fs.readFileSync(IN, 'utf8').split('\n')){
  if (!line.trim()) continue;
  try { rows.push(JSON.parse(line)); } catch(_){}
}

const withRepos = rows.filter(r => (r.repos || 0) > 0);
const vuln = rows.filter(r => (r.findings || []).length > 0)
                 .sort((a,b) => b.findings.length - a.findings.length);
const lowOnly = rows.filter(r => (r.findings||[]).length === 0 && (r.lowrisk||[]).length > 0);

const totalDeps = rows.reduce((s,r) => s + (r.deps || 0), 0);

let md = '';
md += '# Dependency Confusion Scan — Report\n\n';
md += `Generated: ${new Date().toISOString()}\n\n`;
md += '> Detection only. Findings are candidates for **responsible disclosure / bug bounty**. ';
md += 'No packages were published.\n\n';
md += '## Summary\n\n';
md += `- Domains processed: **${rows.length}**\n`;
md += `- Domains with a matched public org/repos: **${withRepos.length}**\n`;
md += `- Total dependency names inspected: **${totalDeps}**\n`;
md += `- **Domains with VULNERABLE packages: ${vuln.length}**\n`;
md += `- Domains with only low-risk (scope-owned) notes: ${lowOnly.length}\n\n`;

md += '## ⚠️ Vulnerable (unclaimed packages — confusable)\n\n';
if (!vuln.length){
  md += '_None found yet._\n\n';
} else {
  md += '| Company | Unclaimed package(s) | Type | Source (repo/file) |\n|---|---|---|---|\n';
  for (const r of vuln){
    for (const f of r.findings){
      const type = f.scopeDecl ? 'scope decl (.npmrc)'
                 : (f.pkg.startsWith('@') ? 'scoped pkg' : 'bare pkg');
      md += `| ${r.domain} | \`${f.pkg}\` | ${type} | \`${f.src || '?'}\` |\n`;
    }
  }
  md += '\n';
}

md += '## ℹ️ Low-risk notes (scope owned, specific pkg missing)\n\n';
if (!lowOnly.length){ md += '_None._\n\n'; }
else {
  for (const r of lowOnly){
    md += `- **${r.domain}**: ${r.lowrisk.map(f => '`'+f.pkg+'`').join(', ')}\n`;
  }
  md += '\n';
}

fs.writeFileSync(OUT, md);
console.log(`report -> ${OUT}  (processed=${rows.length}, withRepos=${withRepos.length}, vuln=${vuln.length})`);
