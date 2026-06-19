#!/usr/bin/env node
/*
 * Verification pass over the VULNERABLE findings in repo-results.jsonl.
 *
 * For each finding it re-checks, live against the npm registry:
 *   - bare/scoped package: is it STILL 404 (unclaimed)?
 *   - scope: does it STILL have zero published packages?
 * It also confirms the source repo/file is reachable (provenance sanity) and
 * flags findings whose scope name has no obvious relation to the company domain
 * (possible org-slug collision) for manual review.
 *
 * Output: verified.jsonl + verified-report.md
 */
const fs = require('fs');
const IN = process.argv[2] || 'repo-results.jsonl';
const OUTJSON = process.argv[3] || 'verified.jsonl';
const OUTMD = process.argv[4] || 'verified-report.md';

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
          '(KHTML, like Gecko) Chrome/124.0 Safari/537.36';
const T = 15000;

function sleep(ms){ return new Promise(r => setTimeout(r, ms)); }
async function fetchT(url){
  const ac = new AbortController(); const t = setTimeout(() => ac.abort(), T);
  try { return await fetch(url, { headers: { 'User-Agent': UA }, signal: ac.signal, redirect: 'follow' }); }
  finally { clearTimeout(t); }
}

async function pkgStatus(name){
  const enc = name.startsWith('@') ? name.replace('/', '%2F') : name;
  try { const r = await fetchT(`https://registry.npmjs.org/${enc}`); return r.status; }
  catch(_){ return 0; }
}
async function scopeCount(scope){
  try {
    const r = await fetchT(`https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(scope)}&size=50`);
    if (!r.ok) return -1;
    const j = await r.json();
    return (j.objects||[]).filter(o => o&&o.package&&typeof o.package.name==='string'
      && o.package.name.startsWith(scope+'/')).length;
  } catch(_){ return -1; }
}
async function urlOk(src){
  // src = "github:slug/repo/branch/path"
  const m = /^github:(.+)$/.exec(src||'');
  if (!m) return null;
  const url = `https://raw.githubusercontent.com/${m[1]}`;
  try { const r = await fetchT(url); return r.ok; } catch(_){ return false; }
}

function related(scope, domain){
  // crude relation heuristic for triage only
  const s = scope.replace(/^@/, '').replace(/[^a-z0-9]/gi,'').toLowerCase();
  const d = domain.split('.')[0].replace(/[^a-z0-9]/gi,'').toLowerCase();
  if (!s || !d) return false;
  return s.includes(d) || d.includes(s) || s.slice(0,4) === d.slice(0,4);
}

// non-npm ecosystems that legitimately 404 on the npm registry and must NOT be
// reported as npm dependency-confusion (Unity UPM / Java / .NET reverse-DNS ids)
const NON_NPM_RE = /^(com|org|net|io|app|dev|co|unity|systems?)\.[a-z0-9][a-z0-9.-]+$/i;
function isNonNpm(pkg){ return !pkg.startsWith('@') && NON_NPM_RE.test(pkg); }

async function main(){
  const rows = [];
  for (const line of fs.readFileSync(IN,'utf8').split('\n')){
    if (!line.trim()) continue;
    try {
      const o = JSON.parse(line);
      if (!(o.findings||[]).length) continue;
      o.findings = o.findings.filter(f => !isNonNpm(f.pkg));   // drop Unity/Java ids
      if (o.findings.length) rows.push(o);
    } catch(_){}
  }
  const ws = fs.createWriteStream(OUTJSON);
  const confirmed = [];
  let n = 0;
  for (const r of rows){
    const out = { domain: r.domain, confirmed: [] };
    for (const f of r.findings){
      const scope = f.pkg.startsWith('@') ? f.pkg.split('/')[0] : null;
      let stillVuln = false, detail = {};
      if (f.scopeDecl || (scope && f.pkg === scope)){
        const c = await scopeCount(scope || f.pkg);
        detail = { scopeCount: c };
        stillVuln = c === 0;
      } else if (scope){
        const st = await pkgStatus(f.pkg);
        const c = await scopeCount(scope);
        detail = { pkgStatus: st, scopeCount: c };
        stillVuln = st === 404 && c === 0;
      } else {
        const st = await pkgStatus(f.pkg);
        detail = { pkgStatus: st };
        stillVuln = st === 404;
      }
      const srcOk = await urlOk(f.src);
      const rel = related(scope || f.pkg, r.domain);
      if (stillVuln){
        out.confirmed.push({ pkg: f.pkg, src: f.src, srcReachable: srcOk,
          relatedToDomain: rel, review: (!rel || srcOk===false), ...detail });
      }
    }
    if (out.confirmed.length){ confirmed.push(out); ws.write(JSON.stringify(out)+'\n'); }
    if (++n % 25 === 0) console.error(`verified ${n}/${rows.length}`);
  }
  ws.end();

  let md = '# Dependency Confusion — Verified Findings\n\n';
  md += `Generated: ${new Date().toISOString()}\n\n`;
  md += `Confirmed-vulnerable domains: **${confirmed.length}**\n\n`;
  md += '| Company | Package | Source | src reachable | relates to domain | needs review |\n';
  md += '|---|---|---|---|---|---|\n';
  for (const r of confirmed){
    for (const c of r.confirmed){
      md += `| ${r.domain} | \`${c.pkg}\` | \`${c.src||'?'}\` | ${c.srcReachable} | ${c.relatedToDomain} | ${c.review?'⚠️ yes':'no'} |\n`;
    }
  }
  fs.writeFileSync(OUTMD, md);
  console.log(`verified domains=${confirmed.length} -> ${OUTMD}`);
}
main().catch(e => { console.error('FATAL', e); process.exit(1); });
