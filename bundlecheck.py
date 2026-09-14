#!/usr/bin/env python3
"""
Deep static re-check (the 'blockmate method'): for each domain, download the
login page + EVERY first-party/CDN JavaScript bundle it references, then grep
for the exact Google Identity call to classify the flow:

  token (ya29)  <- google.accounts.oauth2.initTokenClient
  jwt (id_token)<- google.accounts.id.initialize / .renderButton / g_id_onload
  code          <- google.accounts.oauth2.initCodeClient  (or response_type=code)
  google_only   <- gsi/client present but no specific call found (still unknown)
  none          <- no Google marker at all
"""
import sys, re, csv, os, queue, threading, requests, urllib3
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings()
INFILE, OUTFILE = sys.argv[1], sys.argv[2]
WORKERS = int(os.environ.get("WORKERS", "16"))
TIMEOUT = 12
MAXB = 2_500_000
MAX_JS = 40
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
PATHS = ["", "login", "signin", "sign-in", "sign-up", "signup", "auth/login", "account/login", "users/sign_in"]

INIT_TOKEN = re.compile(r"accounts\.oauth2\.initTokenClient|\binitTokenClient\b", re.I)
INIT_CODE = re.compile(r"accounts\.oauth2\.initCodeClient|\binitCodeClient\b", re.I)
GIS_ID = re.compile(r"accounts\.id\.(?:initialize|renderButton|prompt)|g_id_onload|data-onsuccess", re.I)
RT = re.compile(r"accounts\.google\.com/o/oauth2/(?:v2/)?auth[^\"'\s<>\\]*", re.I)
GSI_ANY = re.compile(r"accounts\.google\.com/gsi|google\.accounts\.(?:id|oauth2)|"
                     r"accounts\.google\.com/o/oauth2|apis\.google\.com/js|data-client_id", re.I)
SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
SKIP = re.compile(r"google-analytics|googletagmanager|gstatic|fonts\.google|doubleclick|"
                  r"facebook|hotjar|fullstory|sentry|intercom|hubspot|segment|cloudflareinsights|"
                  r"gsi/client|apis\.google\.com|recaptcha|gtag/js|clarity|datadog", re.I)
tl = threading.local()


def sess():
    s = getattr(tl, "s", None)
    if s is None:
        s = requests.Session(); s.headers.update({"User-Agent": UA}); tl.s = s
    return s


def get(u):
    try:
        r = sess().get(u, timeout=TIMEOUT, verify=False, allow_redirects=True, stream=True)
        ct = r.headers.get("content-type", "")
        if any(x in ct for x in ("image", "font", "video", "octet", "pdf", "zip")):
            r.close(); return "", u
        body = r.raw.read(MAXB, decode_content=True); r.close()
        return body.decode("utf-8", "ignore"), r.url
    except Exception:
        return "", u


def classify(blob):
    rt = ""
    m = RT.search(blob)
    if m:
        from urllib.parse import parse_qs
        rt = " ".join(parse_qs(urlparse(m.group(0).replace("\\/", "/")).query).get("response_type", []))
    if "id_token" in rt:
        return "jwt", "response_type=id_token"
    if re.search(r"\btoken\b", rt):
        return "token", "response_type=token"
    if INIT_TOKEN.search(blob):
        return "token", "initTokenClient"
    if GIS_ID.search(blob) and not INIT_CODE.search(blob):
        return "jwt", "gis_id:" + GIS_ID.search(blob).group(0)[:22]
    if "code" in rt:
        return "code", "response_type=code"
    if INIT_CODE.search(blob):
        return "code", "initCodeClient"
    if GSI_ANY.search(blob):
        return "google_only", "gsi_present"
    return "none", ""


def analyze(domain):
    combined, js_urls, reached = [], [], False
    urls = [f"https://{domain}/{p}" for p in PATHS]
    for u in urls:
        html, final = get(u)
        if not html:
            continue
        reached = True
        combined.append(html)
        for src in SCRIPT_SRC.findall(html):
            if src.startswith("data:"):
                continue
            au = urljoin(final, src)
            if au.startswith("http") and not SKIP.search(au) and au not in js_urls:
                js_urls.append(au)
        if INIT_TOKEN.search(html) or GIS_ID.search(html) or RT.search(html):
            break
    if not reached:
        return [domain, "unreachable", ""]
    flow, ev = classify("\n".join(combined))
    if flow in ("none", "google_only", "code"):
        for ju in js_urls[:MAX_JS]:
            js, _ = get(ju)
            if not js:
                continue
            combined.append(js)
            if INIT_TOKEN.search(js) or GIS_ID.search(js) or INIT_CODE.search(js) or RT.search(js):
                f2, e2 = classify("\n".join(combined))
                if f2 in ("jwt", "token"):
                    flow, ev = f2, e2; break
        flow, ev = classify("\n".join(combined))
    return [domain, flow, ev]


def main():
    doms = [l.strip().split(",")[0] for l in open(INFILE) if l.strip()]
    done = set()
    if os.path.exists(OUTFILE):
        for r in csv.reader(open(OUTFILE)):
            if r and r[0] != "domain":
                done.add(r[0])
    q = queue.Queue()
    [q.put(d) for d in doms if d not in done]
    newf = not os.path.exists(OUTFILE)
    out = open(OUTFILE, "a", newline=""); w = csv.writer(out); lock = threading.Lock()
    if newf:
        w.writerow(["domain", "flow", "evidence"]); out.flush()

    def worker():
        while True:
            try:
                d = q.get_nowait()
            except queue.Empty:
                return
            try:
                row = analyze(d)
            except Exception as e:
                row = [d, "err", str(e)[:30]]
            with lock:
                w.writerow(row); out.flush()
                print(f"{row[0]:28s} {row[1]:12s} {row[2]}", flush=True)

    ts = [threading.Thread(target=worker, daemon=True) for _ in range(WORKERS)]
    [t.start() for t in ts]; [t.join() for t in ts]
    out.close()


if __name__ == "__main__":
    main()
