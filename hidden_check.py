#!/usr/bin/env python3
"""
Classify each (already-jwt) domain by whether its Google Sign-In is VISIBLY
rendered on the login page, or HIDDEN (present only in the JS code, like
portal.blockmate.io). Processes a shard file, resumable.

Per domain:
  - browser: load login page(s); is a Google button/One-Tap actually VISIBLE?
  - static : fetch login page + first-party JS bundles; is google.accounts.id /
             initTokenClient / initCodeClient / a googleusercontent client_id present?
Verdict:
  visible      -> Google button shown on load (normal)
  hidden       -> Google wired in code but NO visible button  (blockmate-style) ★
  none         -> no Google trace found now
Output CSV: domain, verdict, code_marker, login_url
"""
import sys, re, csv, os, glob, requests, urllib3
from urllib.parse import urljoin, urlparse
from playwright.sync_api import sync_playwright

urllib3.disable_warnings()
INFILE, OUTFILE = sys.argv[1], sys.argv[2]
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
PATHS = ["login", "signin", "sign-in", "sign-up", "signup", "", "auth/login", "users/sign_in"]
INIT_TOKEN = re.compile(r"accounts\.oauth2\.initTokenClient|\binitTokenClient\b", re.I)
INIT_CODE = re.compile(r"accounts\.oauth2\.initCodeClient|\binitCodeClient\b", re.I)
GIS_ID = re.compile(r"accounts\.id\.(?:initialize|renderButton|prompt)|g_id_onload", re.I)
CLIENT = re.compile(r"[0-9]{8,}-[a-z0-9]+\.apps\.googleusercontent\.com", re.I)
SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
SKIP = re.compile(r"google-analytics|googletagmanager|gstatic|fonts\.google|doubleclick|"
                  r"facebook|hotjar|sentry|intercom|hubspot|segment|gsi/client|apis\.google|recaptcha|gtag/js", re.I)

VIS_JS = """() => {
  const vis = e => { if(!e) return false; const r=e.getBoundingClientRect();
    return r.width>0 && r.height>0 && e.offsetParent!==null; };
  // rendered GIS button iframe or One Tap iframe
  for (const f of document.querySelectorAll('iframe')) {
    if (/gsi\\/(button|iframe)/.test(f.src||'') && vis(f)) return true;
  }
  if ([...document.querySelectorAll('#g_id_onload,.g_id_signin,[data-client_id]')].some(vis)) return true;
  // visible element whose short text says Google sign-in
  for (const e of document.querySelectorAll('button,a,[role=button],div,span')) {
    const t=(e.innerText||e.getAttribute('aria-label')||'').trim();
    if (t && t.length<40 && /google/i.test(t) && /sign|log|continue|connect|with|google/i.test(t) && vis(e)) return true;
  }
  return false;
}"""


def sget(u):
    try:
        r = requests.get(u, timeout=10, verify=False, headers={"User-Agent": UA}, allow_redirects=True, stream=True)
        b = r.raw.read(2_000_000, decode_content=True); r.close()
        return b.decode("utf-8", "ignore"), r.url
    except Exception:
        return "", u


def static_code(domain):
    """Return marker string if Google auth code is present in page/bundles."""
    for p in PATHS:
        html, final = sget(f"https://{domain}/{p}")
        if not html:
            continue
        blob = html
        for rx, name in ((INIT_TOKEN, "initTokenClient"), (INIT_CODE, "initCodeClient"), (GIS_ID, "accounts.id"), (CLIENT, "client_id")):
            if rx.search(blob):
                return name
        js = [urljoin(final, s) for s in SRC.findall(html) if not s.startswith("data:")]
        js = [u for u in js if u.startswith("http") and not SKIP.search(u)]
        for ju in js[:30]:
            t, _ = sget(ju)
            if not t:
                continue
            for rx, name in ((INIT_TOKEN, "initTokenClient"), (INIT_CODE, "initCodeClient"), (GIS_ID, "accounts.id"), (CLIENT, "client_id")):
                if rx.search(t):
                    return name
        return ""   # reached a page, no marker
    return "unreachable"


def main():
    doms = [l.strip().split(",")[0] for l in open(INFILE) if l.strip()]
    done = set()
    if os.path.exists(OUTFILE):
        for r in csv.reader(open(OUTFILE)):
            if r and r[0] != "domain":
                done.add(r[0])
    doms = [d for d in doms if d not in done]
    newf = not os.path.exists(OUTFILE)
    exe = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))[-1]
    px = os.environ.get("HTTPS_PROXY")
    out = open(OUTFILE, "a", newline=""); w = csv.writer(out)
    if newf:
        w.writerow(["domain", "verdict", "code_marker", "login_url"]); out.flush()
    with sync_playwright() as p:
        def mk():
            return p.chromium.launch(headless=True, executable_path=exe,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--ignore-certificate-errors",
                      "--ssl-version-max=tls1.2"] + ([f"--proxy-server={px}"] if px else []))
        br = mk(); n = 0
        for d in doms:
            visible = False; used = ""; goog_net = [False]
            try:
                ctx = br.new_context(ignore_https_errors=True, user_agent=UA, viewport={"width": 1280, "height": 900})
                ctx.set_default_navigation_timeout(20000)
                def on_req(r, gn=goog_net):
                    u = r.url
                    if "accounts.google.com/gsi" in u or "accounts.google.com/o/oauth2" in u:
                        gn[0] = True
                ctx.on("request", on_req)
                pg = ctx.new_page()
                for p_ in ["login", "signin", "sign-up", ""]:
                    try:
                        pg.goto(f"https://{d}/{p_}", wait_until="domcontentloaded"); pg.wait_for_timeout(4000)
                        used = f"https://{d}/{p_}"
                        if pg.evaluate(VIS_JS):
                            visible = True
                        if visible or goog_net[0]:
                            break
                    except Exception:
                        continue
                ctx.close()
            except Exception:
                try: br.close()
                except Exception: pass
                br = mk()
            # on-load Google activity (button rendered OR gsi/oauth request fired) => visible/exposed
            if visible or goog_net[0]:
                verdict = "visible"; marker = "on-load"
            else:
                # nothing on load: check the code. client_id/accounts.id in bundle => hidden (blockmate-style)
                marker = static_code(d)
                if marker == "unreachable":
                    verdict = "unreachable"
                elif marker == "":
                    verdict = "none"
                else:
                    verdict = "hidden"
            w.writerow([d, verdict, marker, used]); out.flush()
            print(f"{d:30s} {verdict:12s} {marker}", flush=True)
            n += 1
            if n % 40 == 0:
                try: br.close()
                except Exception: pass
                br = mk()
        try: br.close()
        except Exception: pass
    out.close()


if __name__ == "__main__":
    main()
