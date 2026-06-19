#!/usr/bin/env node
/*
 * Dependency Confusion recon via public code hosting (GitHub / GitLab).
 *
 * Works inside a restricted network policy where company websites are blocked
 * but github.com / gitlab.com / raw.githubusercontent.com / registry.npmjs.org
 * are reachable.
 *
 * Per company domain:
 *   1. Derive candidate org/user slug from the domain (SLD).
 *   2. Find the org on GitHub (and GitLab) and list its public repos.
 *   3. Read package.json (root + common subpaths) and .npmrc from each repo
 *      via raw hosting.
 *   4. Collect every dependency name (scoped @scope/name and bare).
 *   5. Query the public npm registry for each dependency:
 *        CLAIMED      -> exists on npm                        [safe]
 *        SCOPE_OWNED  -> scoped pkg 404 but scope has pkgs    [low risk]
 *        VULNERABLE   -> 404 + scope empty / bare pkg 404     [HIGH risk]
 *
 * DETECTION ONLY — nothing is published. For responsible disclosure.
 *
 * Output: repo-results.jsonl  (one line per domain, appended live, resumable)
 */

const fs = require('fs');

const DOMAINS_FILE = process.argv[2] || 'domains.txt';
const OUT_FILE = process.argv[3] || 'repo-results.jsonl';
const CONCURRENCY = Number(process.env.CONCURRENCY || 6);   // github web is rate-limited
const MAX_REPOS = Number(process.env.MAX_REPOS || 25);
const MAX_BYTES = 3 * 1024 * 1024;
const T = 18000;

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
          '(KHTML, like Gecko) Chrome/124.0 Safari/537.36';

const SCOPED_RE = /@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*/i;

// extra manifest paths probed only AFTER a repo's live branch is confirmed via
// root package.json (keeps request volume low)
const EXTRA_PATHS = [
  '.npmrc', 'frontend/package.json', 'client/package.json',
  'web/package.json', 'app/package.json',
];
const BRANCHES = ['main', 'master'];

const RESERVED_GH = new Set([
  'sponsors','orgs','about','features','marketplace','pricing','login','join',
  'settings','notifications','new','topics','collections','trending','events',
  'security','site','contact','blog','readme','followers','following','stars',
  'apps','marketplace','search','watching','tab','followers',
]);

function sleep(ms){ return new Promise(r => setTimeout(r, ms)); }

async function fetchT(url, opts, timeoutMs){
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs || T);
  try { return await fetch(url, { ...opts, signal: ac.signal, redirect: 'follow' }); }
  finally { clearTimeout(t); }
}

async function getText(url, timeoutMs){
  // retry on rate-limit (429) with backoff
  for (let attempt = 0; attempt < 3; attempt++){
    let r;
    try { r = await fetchT(url, { headers: { 'User-Agent': UA } }, timeoutMs); }
    catch(e){ if (attempt === 2) throw e; await sleep(800 * (attempt+1)); continue; }
    if (r.status === 429 || r.status === 503){
      await sleep(1500 * (attempt+1));
      continue;
    }
    return { status: r.status, ok: r.ok, text: r.ok ? await r.text() : '' };
  }
  return { status: 429, ok: false, text: '' };
}

// ---- derive candidate slug(s) from a domain ----
function slugsFromDomain(domain){
  const parts = domain.toLowerCase().split('.');
  // second-level label: handle co.uk / com.au etc by taking label before a 2-char public-ish suffix
  let sld = parts[0];
  if (parts.length >= 3 && parts[parts.length-2].length <= 3 &&
      ['co','com','org','net','gov','edu','ac'].includes(parts[parts.length-2])){
    sld = parts[parts.length-3];
  } else if (parts.length >= 2){
    sld = parts[parts.length-2];
  }
  const set = new Set([sld]);
  set.add(sld.replace(/[^a-z0-9]/g, ''));      // strip hyphens
  set.add(sld.replace(/-/g, ''));
  return [...set].filter(s => s && s.length >= 2 && s.length <= 39);
}

// ---- npm registry classification (cached globally) ----
const pkgCache = new Map();
const scopeCache = new Map();

async function scopeHasPackages(scope){
  // scope like "@anaconda". Reliable check: search "@scope" and count results
  // whose package name actually lives under "@scope/". (The npm `scope:` search
  // qualifier is unreliable and returns 0 even for populated scopes.)
  if (scopeCache.has(scope)) return scopeCache.get(scope);
  let has = true; // fail-safe: assume owned on error to avoid false positives
  try {
    const r = await fetchT(
      `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(scope)}&size=50`,
      { headers: { 'User-Agent': UA } }, T);
    if (r.ok){
      const j = await r.json();
      const prefix = scope + '/';
      const n = (j.objects || []).filter(o =>
        o && o.package && typeof o.package.name === 'string' &&
        o.package.name.startsWith(prefix)).length;
      has = n > 0;
    }
  } catch(_){}
  scopeCache.set(scope, has);
  return has;
}

async function classify(name){
  if (pkgCache.has(name)) return pkgCache.get(name);
  let cls = 'UNKNOWN';
  try {
    const enc = name.startsWith('@') ? name.replace('/', '%2F') : name;
    const r = await fetchT(`https://registry.npmjs.org/${enc}`,
      { headers: { 'User-Agent': UA } }, T);
    if (r.status === 200) cls = 'CLAIMED';
    else if (r.status === 404){
      if (name.startsWith('@')){
        const owned = await scopeHasPackages(name.split('/')[0]);
        cls = owned ? 'SCOPE_OWNED' : 'VULNERABLE';
      } else cls = 'VULNERABLE';   // bare dep not on npm = internal/private
    }
  } catch(_){}
  pkgCache.set(name, cls);
  return cls;
}

// ---- GitHub: list repos for an org/user slug ----
async function githubRepos(slug){
  const repos = new Set();
  for (const base of [
    `https://github.com/orgs/${slug}/repositories`,
    `https://github.com/${slug}?tab=repositories`,
  ]){
    try {
      const { ok, text } = await getText(base, T);
      if (!ok) continue;
      const re = new RegExp(`href="/${slug}/([A-Za-z0-9._-]+)(?:["/?])`, 'g');
      let m;
      while ((m = re.exec(text)) !== null){
        const name = m[1];
        if (!RESERVED_GH.has(name.toLowerCase())) repos.add(name);
      }
      if (repos.size) break;
    } catch(_){}
  }
  return [...repos].slice(0, MAX_REPOS);
}

// ---- GitLab: list projects for a group/user slug ----
async function gitlabRepos(slug){
  const repos = new Set();
  try {
    const { ok, text } = await getText(`https://gitlab.com/${slug}`, T);
    if (ok){
      const re = new RegExp(`href="/${slug}/([A-Za-z0-9._-]+)(?:["/?])`, 'g');
      let m;
      while ((m = re.exec(text)) !== null) repos.add(m[1]);
    }
  } catch(_){}
  return [...repos].slice(0, MAX_REPOS);
}

// parse deps out of a package.json text
function depsFromPackageJson(text){
  const names = new Set();
  let j;
  try { j = JSON.parse(text); } catch(_){ return names; }
  for (const k of ['dependencies','devDependencies','peerDependencies','optionalDependencies']){
    if (j[k] && typeof j[k] === 'object'){
      for (const dep of Object.keys(j[k])){
        // skip aliases / urls / workspace protocol
        const v = String(j[k][dep] || '');
        // skip non-registry specs: local, workspace, git, url, and npm: aliases
        // (e.g. "react-19": "npm:react@19" is just public react, not internal)
        if (v.startsWith('file:') || v.startsWith('link:') || v.startsWith('workspace:') ||
            v.startsWith('npm:') || v.startsWith('portal:') || v.startsWith('patch:') ||
            v.includes('://') || v.startsWith('git') || v.startsWith('github:')) continue;
        names.add(dep);
      }
    }
  }
  return names;
}

// pull scope names from an .npmrc (e.g. @acme:registry=...)
function scopesFromNpmrc(text){
  const out = new Set();
  const re = /(@[a-z0-9][a-z0-9._-]*)\s*:\s*registry/gi;
  let m; while ((m = re.exec(text)) !== null) out.add(m[1].toLowerCase());
  return out;
}

function rawUrl(host, slug, repo, branch, path){
  return host === 'github'
    ? `https://raw.githubusercontent.com/${slug}/${repo}/${branch}/${path}`
    : `https://gitlab.com/${slug}/${repo}/-/raw/${branch}/${path}`;
}

// depSrc: Map<name, "host:slug/repo/branch/path">  (first source wins)
async function readRepoManifests(host, slug, repo, depSrc){
  const add = (name, branch, path) => {
    if (!depSrc.has(name)) depSrc.set(name, `${host}:${slug}/${repo}/${branch}/${path}`);
  };
  // 1. find the live branch by probing root package.json on main then master
  let liveBranch = null, rootPkg = null;
  for (const branch of BRANCHES){
    let res;
    try { res = await getText(rawUrl(host, slug, repo, branch, 'package.json'), T); }
    catch(_){ continue; }
    if (res.ok && res.text){ liveBranch = branch; rootPkg = res.text; break; }
  }
  if (!liveBranch) return;                       // no root package.json -> skip repo
  for (const d of depsFromPackageJson(rootPkg)) add(d, liveBranch, 'package.json');

  // 2. on the confirmed branch only, probe a few extra manifests + .npmrc
  for (const path of EXTRA_PATHS){
    let res;
    try { res = await getText(rawUrl(host, slug, repo, liveBranch, path), T); }
    catch(_){ continue; }
    if (!res.ok || !res.text) continue;
    if (path.endsWith('.npmrc')){
      for (const s of scopesFromNpmrc(res.text)) add(s + '/_scope', liveBranch, path);
    } else {
      for (const d of depsFromPackageJson(res.text)) add(d, liveBranch, path);
    }
  }
}

// ---- per-domain ----
async function scanDomain(domain){
  const out = { domain, ts: new Date().toISOString(), slugs: [], gh: {}, gl: {},
                repos: 0, deps: 0, findings: [], lowrisk: [], error: null };
  try {
    const slugs = slugsFromDomain(domain);
    out.slugs = slugs;
    const depSrc = new Map();

    for (const slug of slugs){
      const ghRepos = await githubRepos(slug);
      if (ghRepos.length){
        out.gh[slug] = ghRepos;
        out.repos += ghRepos.length;
        for (const repo of ghRepos) await readRepoManifests('github', slug, repo, depSrc);
      }
      const glRepos = await gitlabRepos(slug);
      if (glRepos.length){
        out.gl[slug] = glRepos;
        out.repos += glRepos.length;
        for (const repo of glRepos) await readRepoManifests('gitlab', slug, repo, depSrc);
      }
      if (out.repos > 0) break; // found the org under this slug; stop guessing
    }

    out.deps = depSrc.size;
    for (const [name, src] of depSrc){
      const real = name.endsWith('/_scope') ? name.slice(0, -7) : name;
      const isScopeOnly = name.endsWith('/_scope');
      let cls;
      if (isScopeOnly){
        const owned = await scopeHasPackages(real);
        cls = owned ? 'SCOPE_OWNED' : 'VULNERABLE';
      } else {
        cls = await classify(real);
      }
      if (cls === 'VULNERABLE'){
        out.findings.push({ pkg: real, class: cls, scopeDecl: isScopeOnly, src });
      } else if (cls === 'SCOPE_OWNED'){
        out.lowrisk.push({ pkg: real, class: cls, scopeDecl: isScopeOnly, src });
      }
    }
  } catch(e){ out.error = String(e && e.message || e); }
  return out;
}

// ---- driver ----
async function main(){
  const domains = fs.readFileSync(DOMAINS_FILE, 'utf8')
    .split('\n').map(s => s.trim()).filter(Boolean);

  const done = new Set();
  if (fs.existsSync(OUT_FILE)){
    for (const line of fs.readFileSync(OUT_FILE, 'utf8').split('\n')){
      if (!line.trim()) continue;
      try { done.add(JSON.parse(line).domain); } catch(_){}
    }
  }
  const todo = domains.filter(d => !done.has(d));
  console.error(`[start] total=${domains.length} done=${done.size} todo=${todo.length} conc=${CONCURRENCY}`);

  const ws = fs.createWriteStream(OUT_FILE, { flags: 'a' });
  let idx = 0, processed = 0, withRepos = 0, vuln = 0;

  async function worker(){
    while (idx < todo.length){
      const d = todo[idx++];
      let res;
      try { res = await scanDomain(d); }
      catch(e){ res = { domain: d, error: 'fatal:'+String(e&&e.message||e), findings: [] }; }
      ws.write(JSON.stringify(res) + '\n');
      processed++;
      if (res.repos) withRepos++;
      const hot = (res.findings||[]).filter(f => f.class === 'VULNERABLE');
      if (hot.length) vuln++;
      if (processed % 20 === 0 || hot.length || res.repos){
        const tag = hot.length ? '  <<<VULN ' + hot.map(f=>f.pkg).join(',') :
                    (res.repos ? `  repos=${res.repos} deps=${res.deps}` : '');
        console.error(`[${processed}/${todo.length}] ${res.domain}${tag}`);
      }
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));
  ws.end();
  console.error(`[done] processed=${processed} domainsWithRepos=${withRepos} vulnDomains=${vuln}`);
}

main().catch(e => { console.error('FATAL', e); process.exit(1); });
