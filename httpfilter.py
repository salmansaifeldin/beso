#!/usr/bin/env python3
"""
Fast HTTP pre-filter: fetch a domain's homepage + common login pages and look
for Google-OAuth fingerprints in the static HTML/inline JS. No browser, so it
never hangs (hard per-request timeout). Resumable.

Output CSV columns: domain, google_flag, hint, response_type, evidence
  google_flag: 1 if any Google-OAuth marker found, else 0
  hint: jwt | token | code | google (untyped) | none
  response_type: parsed from any accounts.google.com/o/oauth2 URL if present
"""
import sys, re, csv, os, queue, threading, urllib3, requests
from urllib.parse import urlparse, parse_qs

urllib3.disable_warnings()
INFILE = sys.argv[1]
OUTFILE = sys.argv[2]
WORKERS = 40
TIMEOUT = 7
MAXB = 400_000
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
PATHS = ["", "login", "signin", "sign-in", "account/login", "users/sign_in"]

GAUTH = re.compile(r"accounts\.google\.com/o/oauth2/(?:v2/)?auth[^\"'\s<>]*", re.I)
MARK = re.compile(
    r"accounts\.google\.com/gsi|gsi/client|g_id_onload|google\.accounts\.id|"
    r"google\.accounts\.oauth2|data-client_id|apis\.google\.com/js/(?:platform|api)|"
    r"accounts\.google\.com/o/oauth2|\"plus\.google\.com|googleusercontent", re.I)
GSI_CRED = re.compile(r"gsi/client|g_id_onload|google\.accounts\.id", re.I)

session_local = threading.local()


def sess():
    s = getattr(session_local, "s", None)
    if s is None:
        s = requests.Session()
        s.headers.update({"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})
        session_local.s = s
    return s


def fetch(url):
    try:
        r = sess().get(url, timeout=TIMEOUT, verify=False, allow_redirects=True, stream=True)
        ct = r.headers.get("content-type", "")
        if any(x in ct for x in ("image", "pdf", "octet", "font", "video", "zip")):
            r.close(); return ""
        body = r.raw.read(MAXB, decode_content=True)
        r.close()
        return body.decode("utf-8", "ignore")
    except Exception:
        return ""


def analyze(domain):
    html_all = []
    reachable = False
    for p in PATHS:
        url = f"https://{domain}/{p}"
        h = fetch(url)
        if h:
            reachable = True
            html_all.append(h)
            # short-circuit: if we already see a strong marker, stop early
            if MARK.search(h):
                break
        elif p == "":
            # homepage unreachable over https: try www once
            h = fetch(f"https://www.{domain}/")
            if h:
                reachable = True; html_all.append(h)
                if MARK.search(h):
                    break
    blob = "\n".join(html_all)
    if not reachable:
        return [domain, "0", "none", "", "unreachable"]
    if not MARK.search(blob):
        return [domain, "0", "none", "", ""]
    # found Google markers -> candidate; try to type it
    rt = ""
    m = GAUTH.search(blob)
    if m:
        rt = (parse_qs(urlparse(m.group(0)).query).get("response_type", [""])[0]).lower()
    if rt:
        toks = set(rt.split())
        if "id_token" in toks:
            hint = "jwt"
        elif "token" in toks:
            hint = "token"
        elif "code" in toks:
            hint = "code"
        else:
            hint = "google"
    elif GSI_CRED.search(blob):
        hint = "jwt"
    else:
        hint = "google"
    ev = (m.group(0)[:80] if m else (GSI_CRED.search(blob).group(0) if GSI_CRED.search(blob) else "marker"))
    return [domain, "1", hint, rt, ev]


def main():
    domains = [l.strip() for l in open(INFILE) if l.strip()]
    done = set()
    if os.path.exists(OUTFILE):
        with open(OUTFILE) as f:
            for row in csv.reader(f):
                if row:
                    done.add(row[0])
    todo = [d for d in domains if d not in done]
    newfile = not os.path.exists(OUTFILE)
    q = queue.Queue()
    for d in todo:
        q.put(d)
    lock = threading.Lock()
    out = open(OUTFILE, "a", newline="")
    w = csv.writer(out)
    if newfile:
        w.writerow(["domain", "google_flag", "hint", "response_type", "evidence"]); out.flush()

    def worker():
        while True:
            try:
                d = q.get_nowait()
            except queue.Empty:
                return
            try:
                row = analyze(d)
            except Exception as e:
                row = [d, "0", "none", "", "ERR:" + str(e)[:30]]
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
