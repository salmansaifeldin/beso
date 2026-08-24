# Google SSO Flow Scanner

Detects, for each domain, whether its login offers **"Sign in with Google"** and —
crucially — **which OAuth flow** it uses, so we can keep only the ones where a
**token is returned to the app**:

| Verdict | Meaning | Kept? |
|---------|---------|-------|
| `jwt`   | Google returns an **id_token (JWT)** to the site (GIS credential or `response_type=id_token`) | ✅ WANT |
| `token` | Google returns an **access_token `ya29…`** to the site (`response_type=token` / `initTokenClient`) | ✅ WANT |
| `code`  | Only an **auth code** is returned (server-side exchange) | ❌ excluded |
| `google_unknown` | Google present but flow not captured | – |
| `none`  | No Google login found | – |

## Final results (list of 8,195 domains)

- `google_token_login_domains.txt` — **311** WANT domains (287 JWT + 24 ya29)
- `google_jwt_domains.txt` — 287 JWT
- `google_token_ya29_domains.txt` — 24 ya29 access_token
- `google_code_excluded_domains.txt` — 529 code-flow (excluded)
- `google_sso_results.csv` — full evidence table (verdict, evidence, login_url, final_url)

## How it works

### 1. `google_scan.py` — the per-domain detector (Playwright / headless Chromium)
For each domain it:
1. **DNS gate** (hard 5 s timeout) — skip dead hosts fast.
2. **Find the login page** — follow a login link from the homepage, else probe
   `/login`, `/signin`, and `app.` / `accounts.` / `login.` / `secure.` / `my.` subdomains.
3. **Render it** and capture every network request to `accounts.google.com`,
   plus the DOM (for GIS markers like `g_id_onload` / `google.accounts.id`).
4. **Reveal hidden providers** — click "more options / continue with SSO /
   work email" expanders, and trigger the GIS button iframe.
5. **Classify the flow** from the captured `response_type` (`classify_google`):
   - `id_token` → **jwt**, `token` → **ya29**, GIS credential → **jwt**,
     `code` → **code**.

Key anti-hang / anti-bot measures: DNS pre-gate, blocked analytics/ads/media
hosts, `navigator.webdriver` spoofing, per-context timeouts, and periodic
browser recycling (every 40 domains) to bound memory.

Run a single shard directly:
```bash
FAST=1 python3 google_scan.py domains.txt out.csv -v
```

### 2. `gbatch.sh` — the parallel orchestrator
Runs **8 shards in parallel** for a bounded window (default 560 s), then
consolidates. **Resumable**: each call re-reads what's done, reshuffles the
remainder into 8 fresh shards, and continues. Loop it until `remaining=0`:
```bash
while :; do bash gbatch.sh 560; done   # reads domains_all.txt, writes scan_work_g/
```

### 3. `aggregate_results.py` — build the final files
```bash
python3 aggregate_results.py scan_work_g 8195
```

## Requirements
- Python 3, `playwright` (`pip install playwright`) with Chromium
  (`playwright install chromium`, or set `PLAYWRIGHT_BROWSERS_PATH`).
- Input: `domains_all.txt` (one domain per line).

## Notes / limitations
- The verdict is **confirmed from real OAuth traffic** (the captured
  `response_type`), not guessed from HTML — so JWT vs ya29 vs code is reliable.
- A tiny number of sites gate Google behind email-first steps the crawler
  can't complete; those land in `google_unknown`.
- Blind crawling only pays off on lists with real consumer-Google login. To find
  Google-token sites across a very large universe, prefer a **source-code
  fingerprint search** (PublicWWW / HTTPArchive-BigQuery) for
  `google.accounts.oauth2.initTokenClient` (ya29) and `google.accounts.id`
  (JWT), then confirm the candidates with this scanner.
