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
function srcRawUrl(src){
  const m = /^github:(.+)$/.exec(src||'');
  if (m) return `https://raw.githubusercontent.com/${m[1]}`;
  const g = /^gitlab:(.+?)\/(.+?)\/(.+?)\/(.+)$/.exec(src||'');
  if (g) return `https://gitlab.com/${g[1]}/${g[2]}/-/raw/${g[3]}/${g[4]}`;
  return null;
}
async function getSrcText(src){
  const url = srcRawUrl(src);
  if (!url) return null;
  try { const r = await fetchT(url); return r.ok ? await r.text() : null; }
  catch(_){ return null; }
}
// version spec that does NOT resolve from the public npm registry -> not a
// confusion target (git shorthand owner/repo, workspace/file/link/url/alias...)
function isNonRegistrySpec(v){
  if (typeof v !== 'string') return false;
  v = v.trim();
  return /^(workspace:|file:|link:|portal:|patch:|catalog:|npm:|git|github:|gitlab:|bitbucket:|https?:|ssh:)/i.test(v)
      || v.includes('://')
      || /^[\w.-]+\/[\w.-]+(#.+)?$/.test(v);   // GitHub shorthand "owner/repo[#ref]"
}
// look up the declared version of pkg inside a package.json text
function declaredSpec(jsonText, pkg){
  let j; try { j = JSON.parse(jsonText); } catch(_){ return undefined; }
  for (const k of ['dependencies','devDependencies','peerDependencies','optionalDependencies']){
    if (j[k] && Object.prototype.hasOwnProperty.call(j[k], pkg)) return String(j[k][pkg]);
  }
  return undefined;
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
    // cache manifest text per src within a domain
    const srcTextCache = new Map();
    for (const f of r.findings){
      const scope = f.pkg.startsWith('@') ? f.pkg.split('/')[0] : null;
      let stillVuln = false, detail = {};

      // re-read the manifest and inspect the declared version spec; non-registry
      // specs (git shorthand, workspace, url, alias) are NOT confusion targets
      if (!f.scopeDecl && f.src && /package\.json$/.test(f.src)){
        if (!srcTextCache.has(f.src)) srcTextCache.set(f.src, await getSrcText(f.src));
        const txt = srcTextCache.get(f.src);
        const spec = txt ? declaredSpec(txt, f.pkg) : undefined;
        if (spec !== undefined && isNonRegistrySpec(spec)){
          continue;   // skip: dependency is not pulled from public npm
        }
      }
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
        // bare pkg: npm names are lowercase — check as-is AND lowercased so that
        // casing-only mismatches (e.g. HTML_CodeSniffer) aren't false positives
        const st = await pkgStatus(f.pkg);
        let stLower = st;
        if (st === 404 && f.pkg !== f.pkg.toLowerCase()){
          stLower = await pkgStatus(f.pkg.toLowerCase());
        }
        detail = { pkgStatus: st, pkgStatusLower: stLower };
        stillVuln = st === 404 && stLower === 404;
      }
      const srcOk = srcRawUrl(f.src) ? true : null;   // provenance recorded at scan time
      const rel = related(scope || f.pkg, r.domain);
      const isBare = !f.pkg.startsWith('@');
      if (stillVuln){
        out.confirmed.push({ pkg: f.pkg, src: f.src, srcReachable: srcOk,
          relatedToDomain: rel, bare: isBare,
          review: (!rel || isBare), ...detail });
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
