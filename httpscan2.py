#!/usr/bin/env python3
"""
Proxy-friendly Google-SSO-flow detector (no browser).

For each domain it fetches the homepage + common login pages AND the site's own
first-party JavaScript bundles (where the Google Identity calls actually live),
then classifies the OAuth flow from the fingerprints found:

  token (ya29)  <- google.accounts.oauth2.initTokenClient  OR  response_type=token
  jwt (id_token)<- google.accounts.id(.initialize) / g_id_onload / data-client_id
                   / response_type=id_token
  code          <- google.accounts.oauth2.initCodeClient / response_type=code (only)
  google_unknown<- gsi/client present but flow markers not captured
  none          <- no Google login

Works through an HTTPS_PROXY (uses requests, which honours the env proxy).
Output CSV: domain, flow, confirmed, evidence, login_url, final_url
"""
import sys, re, csv, os, queue, threading, urllib3, requests
from urllib.parse import urljoin, urlparse, parse_qs

urllib3.disable_warnings()
INFILE = sys.argv[1]
OUTFILE = sys.argv[2] if len(sys.argv) > 2 else "httpscan2_out.csv"
WORKERS = int(os.environ.get("WORKERS", "24"))
TIMEOUT = 8
MAXB = 800_000
MAX_JS = 22
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
PATHS = ["", "login", "signin", "sign-in", "account/login", "users/sign_in", "auth/login"]
SUBS = ["app", "accounts", "login", "secure", "my", "dashboard", "auth"]

OAUTH_URL = re.compile(r"accounts\.google\.com/o/oauth2/(?:v2/)?auth[^\"'\s<>\\]*", re.I)
INIT_TOKEN = re.compile(r"accounts\.oauth2\.initTokenClient|initTokenClient", re.I)
INIT_CODE = re.compile(r"accounts\.oauth2\.initCodeClient|initCodeClient", re.I)
# strong id_token/JWT setup markers (bare gsi/client alone is NOT enough — it
# loads for code flows too — so it's only counted under GIS_ANY)
GIS_ID = re.compile(r"google\.accounts\.id\.initialize|g_id_onload|"
                    r"data-client_id|data-onsuccess", re.I)
GIS_ANY = re.compile(r"accounts\.google\.com/gsi|google\.accounts\.oauth2|"
                     r"accounts\.google\.com/o/oauth2|apis\.google\.com/js/(?:platform|api)", re.I)
SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
# prioritise bundles likely to contain auth code
JS_PRIORITY = re.compile(r"login|auth|sign|main|app|index|vendor|chunk|bundle|runtime", re.I)
# third-party hosts whose JS never contains the site's own Google-auth call
JS_SKIP_HOST = re.compile(
    r"google-analytics|googletagmanager|gstatic|fonts\.google|doubleclick|"
    r"googlesyndication|facebook|hotjar|fullstory|mixpanel|segment|sentry|"
    r"intercom|hubspot|cloudflareinsights|newrelic|datadog|cookiebot|"
    r"gsi/client|apis\.google\.com|recaptcha|gtag/js", re.I)

session_local = threading.local()


def sess():
    s = getattr(session_local, "s", None)
    if s is None:
        s = requests.Session()
        s.headers.update({"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})
        session_local.s = s
    return s


def get(url):
    try:
        r = sess().get(url, timeout=TIMEOUT, verify=False, allow_redirects=True, stream=True)
        ct = r.headers.get("content-type", "")
        if any(x in ct for x in ("image", "pdf", "octet", "font", "video", "zip", "audio")):
            r.close(); return "", url
        body = r.raw.read(MAXB, decode_content=True)
        final = r.url
        r.close()
        return body.decode("utf-8", "ignore"), final
    except Exception:
        return "", url


def same_site(host, domain):
    return host == domain or host.endswith("." + domain) or domain.endswith("." + host)


def classify(blob):
    """Return (flow, evidence) from combined HTML+JS text."""
    rtypes = []
    for m in OAUTH_URL.finditer(blob):
        rt = (parse_qs(urlparse(m.group(0).replace("\\/", "/")).query).get("response_type", [""])[0]).lower()
        if rt:
            rtypes.append(rt)
    toks = set(t for rt in rtypes for t in rt.split())
    if "id_token" in toks:
        return "jwt", "response_type=" + ";".join(sorted(set(rtypes)))
    if "token" in toks:
        return "token", "response_type=" + ";".join(sorted(set(rtypes)))
    if INIT_TOKEN.search(blob):
        return "token", "initTokenClient"
    if GIS_ID.search(blob) and "code" not in toks and not INIT_CODE.search(blob):
        return "jwt", "gis_credential:" + GIS_ID.search(blob).group(0)[:24]
    if "code" in toks:
        return "code", "response_type=code"
    if INIT_CODE.search(blob):
        return "code", "initCodeClient"
    if GIS_ANY.search(blob):
        return "google_unknown", "gsi_only"
    return "none", ""


def analyze(domain):
    login_url = ""
    final_url = ""
    combined = []
    js_urls = []
    reached = False
    # 1) fetch page candidates
    urls = [f"https://{domain}/{p}" for p in PATHS]
    urls += [f"https://{s}.{domain}/login" for s in SUBS[:4]]
    for url in urls:
        html, final = get(url)
        if not html:
            continue
        reached = True
        if not login_url and url != f"https://{domain}/":
            login_url = url; final_url = final
        combined.append(html)
        # collect script srcs (first-party AND cross-origin app bundles on CDNs;
        # only obvious third-party analytics/library hosts are skipped)
        for src in SCRIPT_SRC.findall(html):
            if src.startswith("data:"):
                continue
            absu = urljoin(final, src)
            if not absu.lower().startswith("http") or JS_SKIP_HOST.search(absu):
                continue
            if absu not in js_urls:
                h = urlparse(absu).netloc.split(":")[0].lower()
                js_urls.append((0 if same_site(h, domain) else 1, absu))
        # early strong hit?
        if INIT_TOKEN.search(html) or GIS_ID.search(html) or OAUTH_URL.search(html):
            break
    if not reached:
        return [domain, "none", "", "unreachable", "", ""]
    blob = "\n".join(combined)
    flow, ev = classify(blob)
    # 2) if not yet a token/jwt hit, dig into first-party JS bundles
    if flow in ("none", "google_unknown", "code"):
        # order: same-site first, then auth/app-named bundles, then the rest
        js_urls.sort(key=lambda t: (t[0], 0 if JS_PRIORITY.search(t[1]) else 1))
        for _pri, ju in js_urls[:MAX_JS]:
            js, _ = get(ju)
            if not js:
                continue
            combined.append(js)
            if INIT_TOKEN.search(js) or GIS_ID.search(js) or OAUTH_URL.search(js) or INIT_CODE.search(js):
                flow, ev = classify("\n".join(combined))
                if flow in ("jwt", "token"):
                    break
        flow, ev = classify("\n".join(combined))
    conf = "yes" if flow in ("jwt", "token") else ""
    if not login_url:
        login_url = f"https://{domain}/"
    return [domain, flow, conf, ev, login_url, final_url]


def main():
    domains = [l.strip() for l in open(INFILE) if l.strip()]
    done = set()
    if os.path.exists(OUTFILE):
        for r in csv.reader(open(OUTFILE)):
            if r and r[0] != "domain":
                done.add(r[0])
    todo = [d for d in domains if d not in done]
    newfile = not os.path.exists(OUTFILE)
    q = queue.Queue()
    for d in todo:
        q.put(d)
    lock = threading.Lock()
    out = open(OUTFILE, "a", newline="")
    w = csv.writer(out)
    if newfile:
        w.writerow(["domain", "flow", "confirmed", "evidence", "login_url", "final_url"]); out.flush()

    def worker():
        while True:
            try:
                d = q.get_nowait()
            except queue.Empty:
                return
            try:
                row = analyze(d)
            except Exception as e:
                row = [d, "none", "", "ERR:" + str(e)[:30], "", ""]
            with lock:
                w.writerow(row); out.flush()
            q.task_done()

    ts = [threading.Thread(target=worker, daemon=True) for _ in range(WORKERS)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    out.close()


if __name__ == "__main__":
    main()
