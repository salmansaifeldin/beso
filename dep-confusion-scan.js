#!/usr/bin/env node
/*
 * Dependency Confusion reconnaissance scanner.
 *
 * For each domain:
 *   1. Fetch homepage HTML
 *   2. Extract JS bundle URLs (and a few obvious build paths)
 *   3. Download JS (streamed, size-capped, NOT stored on disk)
 *   4. Extract scoped npm package names  (@scope/name)
 *   5. Query the public npm registry to decide if each package / scope is
 *      claimed or unclaimed.
 *
 * Classification per scoped package:
 *   CLAIMED      -> package exists on npm (registry 200)             [safe]
 *   SCOPE_OWNED  -> package 404 but scope has other published pkgs   [low risk]
 *   VULNERABLE   -> package 404 AND scope has zero published pkgs    [HIGH risk]
 *
 * Output: results.jsonl (one JSON object per processed domain, appended live)
 *         Resumable: re-running skips domains already in results.jsonl.
 *
 * DETECTION ONLY. No packages are published. Findings are for responsible
 * disclosure / bug bounty reporting.
 */

const fs = require('fs');
const path = require('path');

// ---- config ----
const DOMAINS_FILE = process.argv[2] || 'domains.txt';
const OUT_FILE = process.argv[3] || 'results.jsonl';
const DOMAIN_CONCURRENCY = Number(process.env.CONCURRENCY || 24);
const MAX_JS_PER_DOMAIN = 14;
const MAX_JS_BYTES = 5 * 1024 * 1024;     // 5MB cap per JS file
const HTML_TIMEOUT_MS = 15000;
const JS_TIMEOUT_MS = 20000;
const REGISTRY_TIMEOUT_MS = 15000;

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
          '(KHTML, like Gecko) Chrome/124.0 Safari/537.36';

const BROWSER_HEADERS = {
  'User-Agent': UA,
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
  'Sec-Fetch-Dest': 'document',
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Site': 'none',
  'Upgrade-Insecure-Requests': '1',
};

// scoped npm package:  @scope/name   (scope & name follow npm naming rules)
const SCOPED_RE = /@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*/gi;

// public scopes we never want to flag (registry would say so anyway, this just
// saves network round-trips for the most common ones)
const KNOWN_PUBLIC = new Set([
  '@babel','@types','@angular','@vue','@mui','@emotion','@reduxjs','@sentry',
  '@stripe','@aws-sdk','@aws-crypto','@floating-ui','@radix-ui','@tanstack',
  '@popperjs','@fortawesome','@react-aria','@react-stately','@react-spring',
  '@apollo','@graphql','@nestjs','@next','@vercel','@swc','@esbuild','@rollup',
  '@webpack','@storybook','@testing-library','@hookform','@tiptap','@firebase',
  '@google-cloud','@googlemaps','@datadog','@segment','@auth0','@okta','@hubspot',
  '@cloudflare','@svgr','@ant-design','@chakra-ui','@mantine','@nextui-org',
  '@heroicons','@tabler','@iconify','@lottiefiles','@formatjs','@lingui',
  '@dnd-kit','@tippyjs','@material-ui','@fullcalendar','@fortawesome',
  '@react-native','@react-navigation','@expo','@shopify','@adobe','@contentful',
  '@sanity','@strapi','@prisma','@trpc','@unleash','@growthbook','@launchdarkly',
  '@amplitude','@mixpanel','@intercom','@sendbird','@stream-io','@livekit',
  '@daily-co','@twilio','@vonage','@agora','@zoom','@microsoft','@azure',
  '@aws-amplify','@supabase','@clerk','@workos','@descope','@magic-sdk',
  '@walletconnect','@web3-react','@solana','@coinbase','@metamask','@ethersproject',
  '@openzeppelin','@uniswap','@chainlink','@thirdweb','@rainbow-me','@wagmi',
  '@tailwindcss','@headlessui','@vueuse','@nuxt','@nuxtjs','@pinia','@remix-run',
  '@gatsbyjs','@astrojs','@sveltejs','@playwright','@cypress','@jest','@vitest',
  '@grpc','@protobufjs','@bufbuild','@connectrpc','@opentelemetry','@grafana',
  '@elastic','@algolia','@meilisearch','@typesense','@pusher','@ably',
  '@fingerprintjs','@datadog-browser','@newrelic','@bugsnag','@rollbar',
  '@logrocket','@hotjar','@fullstory','@posthog','@plausible','@vimeo',
  '@mux','@cloudinary','@imgix','@uploadcare','@uppy','@ffmpeg','@tensorflow',
  '@huggingface','@langchain','@pinecone-database','@anthropic-ai','@openai',
  '@react-pdf','@react-three','@react-google-maps','@visx','@nivo','@vx',
  '@uiw','@codemirror','@monaco-editor','@lexical','@slate','@dnd','@use-gesture',
  '@react-icons','@phosphor-icons','@primer','@carbon','@fluentui','@spectrum-css',
]);

// ---- tiny helpers ----
function sleep(ms){ return new Promise(r => setTimeout(r, ms)); }

async function fetchWithTimeout(url, opts, timeoutMs){
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    return await fetch(url, { ...opts, signal: ac.signal, redirect: 'follow' });
  } finally {
    clearTimeout(t);
  }
}

// read body but stop after maxBytes
async function readCapped(resp, maxBytes){
  const reader = resp.body.getReader();
  const chunks = [];
  let total = 0;
  while (true){
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    chunks.push(value);
    if (total >= maxBytes){ try { await reader.cancel(); } catch(_){} break; }
  }
  return Buffer.concat(chunks).toString('utf8');
}

function extractScriptUrls(html, baseUrl){
  const urls = new Set();
  const re = /<script[^>]+src\s*=\s*["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html)) !== null){
    try { urls.add(new URL(m[1], baseUrl).href); } catch(_){}
  }
  // also modulepreload / link rel as=script
  const re2 = /<link[^>]+href\s*=\s*["']([^"']+\.js[^"']*)["']/gi;
  while ((m = re2.exec(html)) !== null){
    try { urls.add(new URL(m[1], baseUrl).href); } catch(_){}
  }
  return [...urls];
}

// ---- npm registry classification with global cache ----
const pkgCache = new Map();   // "@scope/name" -> classification
const scopeCache = new Map(); // "@scope" -> boolean (has published pkgs)

async function scopeHasPackages(scope){
  if (scopeCache.has(scope)) return scopeCache.get(scope);
  let has = true; // fail-safe: assume owned on error (avoid false positives)
  try {
    const q = encodeURIComponent('scope:' + scope.slice(1));
    const r = await fetchWithTimeout(
      `https://registry.npmjs.org/-/v1/search?text=${q}&size=1`,
      { headers: { 'User-Agent': UA } }, REGISTRY_TIMEOUT_MS);
    if (r.ok){
      const j = await r.json();
      has = (j.total || 0) > 0;
    }
  } catch(_){}
  scopeCache.set(scope, has);
  return has;
}

async function classifyPackage(full){
  if (pkgCache.has(full)) return pkgCache.get(full);
  const scope = full.split('/')[0];
  if (KNOWN_PUBLIC.has(scope)){ pkgCache.set(full, 'CLAIMED'); return 'CLAIMED'; }

  let cls = 'UNKNOWN';
  try {
    const enc = full.replace('/', '%2F');
    const r = await fetchWithTimeout(`https://registry.npmjs.org/${enc}`,
      { headers: { 'User-Agent': UA } }, REGISTRY_TIMEOUT_MS);
    if (r.status === 200){
      cls = 'CLAIMED';
    } else if (r.status === 404){
      const owned = await scopeHasPackages(scope);
      cls = owned ? 'SCOPE_OWNED' : 'VULNERABLE';
    } else {
      cls = 'UNKNOWN';
    }
  } catch(_){
    cls = 'UNKNOWN';
  }
  pkgCache.set(full, cls);
  return cls;
}

// pull sourceMappingURL out of a JS body (last one wins, ignore data: URIs)
function extractSourceMapUrl(body, jsUrl){
  const re = /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/g;
  let m, last = null;
  while ((m = re.exec(body)) !== null) last = m[1];
  if (!last || last.startsWith('data:')) return null;
  try { return new URL(last, jsUrl).href; } catch(_){ return null; }
}

// ---- per-domain scan ----
async function scanDomain(domain){
  const out = { domain, ts: new Date().toISOString(), status: null, js: 0, maps: 0,
                scoped: [], findings: [], error: null };
  let html = '';
  let baseUrl = null;
  for (const host of [domain, 'www.' + domain]){
    for (const scheme of ['https://', 'http://']){
      try {
        const r = await fetchWithTimeout(scheme + host,
          { headers: BROWSER_HEADERS }, HTML_TIMEOUT_MS);
        out.status = r.status;
        baseUrl = r.url || (scheme + host);
        const body = await readCapped(r, MAX_JS_BYTES);
        if (r.ok && body.length > 200){ html = body; }
        break;
      } catch(e){ out.error = String(e && e.message || e); }
    }
    if (html) break;
  }
  if (!html){ return out; }
  out.error = null;

  let jsUrls = extractScriptUrls(html, baseUrl).slice(0, MAX_JS_PER_DOMAIN);

  const scopedSet = new Set();
  // also scan inline HTML itself
  for (const m of html.matchAll(SCOPED_RE)) scopedSet.add(m[0].toLowerCase());

  for (const u of jsUrls){
    let body = '';
    try {
      const r = await fetchWithTimeout(u, { headers: { 'User-Agent': UA } }, JS_TIMEOUT_MS);
      if (!r.ok || !r.body) continue;
      body = await readCapped(r, MAX_JS_BYTES);
      out.js++;
      for (const m of body.matchAll(SCOPED_RE)) scopedSet.add(m[0].toLowerCase());
    } catch(_){ continue; }

    // follow source map — original module paths live here (node_modules/@scope/...)
    const mapUrl = extractSourceMapUrl(body, u);
    if (mapUrl){
      try {
        const mr = await fetchWithTimeout(mapUrl, { headers: { 'User-Agent': UA } }, JS_TIMEOUT_MS);
        if (mr.ok && mr.body){
          const mapTxt = await readCapped(mr, MAX_JS_BYTES);
          out.maps++;
          for (const m of mapTxt.matchAll(SCOPED_RE)) scopedSet.add(m[0].toLowerCase());
        }
      } catch(_){}
    }
  }

  out.scoped = [...scopedSet].sort();

  // classify each scoped pkg
  for (const full of out.scoped){
    const cls = await classifyPackage(full);
    if (cls === 'VULNERABLE' || cls === 'SCOPE_OWNED'){
      out.findings.push({ pkg: full, scope: full.split('/')[0], class: cls });
    }
  }
  return out;
}

// ---- concurrency pool driver ----
async function main(){
  const domains = fs.readFileSync(DOMAINS_FILE, 'utf8')
    .split('\n').map(s => s.trim()).filter(Boolean);

  // resume support
  const done = new Set();
  if (fs.existsSync(OUT_FILE)){
    for (const line of fs.readFileSync(OUT_FILE, 'utf8').split('\n')){
      if (!line.trim()) continue;
      try { done.add(JSON.parse(line).domain); } catch(_){}
    }
  }
  const todo = domains.filter(d => !done.has(d));
  console.error(`[start] total=${domains.length} done=${done.size} todo=${todo.length} concurrency=${DOMAIN_CONCURRENCY}`);

  const ws = fs.createWriteStream(OUT_FILE, { flags: 'a' });
  let idx = 0, processed = 0, vulnDomains = 0;

  async function worker(){
    while (idx < todo.length){
      const d = todo[idx++];
      let res;
      try { res = await scanDomain(d); }
      catch(e){ res = { domain: d, error: 'fatal:' + String(e && e.message || e), findings: [] }; }
      ws.write(JSON.stringify(res) + '\n');
      processed++;
      if (res.findings && res.findings.length) vulnDomains++;
      if (processed % 25 === 0 || (res.findings && res.findings.some(f => f.class === 'VULNERABLE'))){
        const hit = res.findings && res.findings.length
          ? '  <<< ' + res.findings.map(f => `${f.pkg}[${f.class}]`).join(', ')
          : '';
        console.error(`[${processed}/${todo.length}] ${res.domain} js=${res.js||0} scoped=${(res.scoped||[]).length}${hit}`);
      }
    }
  }

  const workers = Array.from({ length: DOMAIN_CONCURRENCY }, () => worker());
  await Promise.all(workers);
  ws.end();
  console.error(`[done] processed=${processed} domainsWithFindings=${vulnDomains}`);
}

main().catch(e => { console.error('FATAL', e); process.exit(1); });
