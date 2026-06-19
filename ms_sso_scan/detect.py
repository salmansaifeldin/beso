#!/usr/bin/env python3
"""
Detect domains that offer Microsoft SSO ("Sign in with Microsoft" / Azure AD /
Entra ID / Office 365) on their login pages.

Strategy per domain:
  1. Fetch homepage (follow redirects).
  2. Discover login-ish links from homepage HTML, plus a list of common login paths.
  3. Fetch a bounded set of candidate login pages.
  4. Inspect raw HTML + final redirect URLs for Microsoft SSO signals.

A domain is classified MS-SSO if we find EITHER:
  - a strong URL signal: login.microsoftonline.com / login.windows.net /
    sts.windows.net / aadcdn.ms... / login.microsoftonline.us / msft auth CDNs, OR
  - an explicit Microsoft sign-in BUTTON phrase (not a bare "Microsoft" mention).

Evidence (url + matched signal + snippet) is recorded so results are auditable.
"""
import re
import sys
import csv
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
urllib3.disable_warnings()

INFILE = sys.argv[1] if len(sys.argv) > 1 else "domains.txt"
OUTDIR = sys.argv[2] if len(sys.argv) > 2 else "."
WORKERS = int(sys.argv[3]) if len(sys.argv) > 3 else 64

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

TIMEOUT = 9
MAX_PAGES = 6          # max candidate pages fetched per domain
MAX_BYTES = 600_000    # cap body read per page

# Strong URL signals -> Microsoft identity platform endpoints / CDNs.
URL_SIGNALS = [
    "login.microsoftonline.com",
    "login.microsoftonline.us",
    "login.windows.net",
    "sts.windows.net",
    "login.live.com",
    "aadcdn.msftauth.net",
    "aadcdn.msauth.net",
    "login.microsoft.com",
    "msftauthimages",
]

# Explicit Microsoft sign-in button / SSO phrases (case-insensitive).
PHRASE_SIGNALS = [
    "sign in with microsoft",
    "log in with microsoft",
    "login with microsoft",
    "continue with microsoft",
    "signin with microsoft",
    "sign-in with microsoft",
    "sign in with azure",
    "login with azure",
    "continue with azure",
    "sign in with office 365",
    "sign in with office365",
    "sign in with microsoft 365",
    "continue with microsoft 365",
    "sign in with entra",
    "microsoft entra",
    "continue with microsoft sso",
    "microsoft sso",
    "sign in with your organizational account",
    "sign in with your work or school account",
    "sign in with your microsoft account",
    "use microsoft credentials",
    "sign in with microsoft account",
    "log in with azure ad",
    "sign in with azure ad",
    "azure active directory",
    "sign in with o365",
]

# Path candidates to probe for login pages.
LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/sign_in", "/auth/login", "/users/sign_in",
    "/account/login", "/accounts/login", "/app/login", "/sso", "/sso/login",
    "/auth", "/user/login", "/login/", "/portal/login", "/secure/login",
]

# Anchor text hints to follow links from homepage.
LINK_TEXT_HINTS = re.compile(r"(log\s?in|sign\s?in|sign\s?up|get started|sso|portal|account|my account|dashboard)", re.I)

url_re = re.compile(r"https?://[^\s\"'<>\\)]+", re.I)


def make_session():
    s = requests.Session()
    s.headers.update(HEADERS)
    retry = Retry(total=1, backoff_factor=0.2, status_forcelist=[502, 503, 504],
                  allowed_methods=["GET", "HEAD"])
    ad = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=8)
    s.mount("http://", ad)
    s.mount("https://", ad)
    return s


def fetch(session, url):
    try:
        r = session.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False, stream=True)
        chain = [h.url for h in r.history] + [r.url]
        body = b""
        for chunk in r.iter_content(8192):
            body += chunk
            if len(body) >= MAX_BYTES:
                break
        r.close()
        text = body.decode(r.encoding or "utf-8", errors="ignore")
        return r.status_code, chain, text
    except Exception:
        return None, [], ""


def scan_text(text, chain):
    low = text.lower()
    hay = low + " " + " ".join(chain).lower()
    for sig in URL_SIGNALS:
        if sig in hay:
            return ("url", sig)
    for ph in PHRASE_SIGNALS:
        if ph in low:
            return ("phrase", ph)
    return None


def discover_links(base, text):
    """Return up to a few same-site login-ish absolute URLs from homepage HTML."""
    found = []
    seen = set()
    # anchors with hint text
    for m in re.finditer(r'<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', text, re.I | re.S):
        href, label = m.group(1), re.sub(r"<[^>]+>", " ", m.group(2))
        if LINK_TEXT_HINTS.search(label) or LINK_TEXT_HINTS.search(href):
            absu = urljoin(base, href)
            p = urlparse(absu)
            if p.scheme in ("http", "https"):
                key = absu.split("#")[0]
                if key not in seen:
                    seen.add(key)
                    found.append(absu)
        if len(found) >= 4:
            break
    return found


def check_domain(domain):
    domain = domain.strip()
    if not domain:
        return None
    session = make_session()
    evidence = None
    tried = []
    home_html = ""
    home_base = None

    # 1) homepage (https then http)
    for scheme in ("https://", "http://"):
        url = scheme + domain
        code, chain, text = fetch(session, url)
        tried.append(url)
        if code is not None:
            home_base = chain[-1] if chain else url
            home_html = text
            hit = scan_text(text, chain)
            if hit:
                evidence = (home_base, hit[0], hit[1])
            break

    candidates = []
    if home_base:
        candidates.extend(discover_links(home_base, home_html))
    root = (home_base or ("https://" + domain)).rstrip("/")
    pr = urlparse(root)
    origin = f"{pr.scheme}://{pr.netloc}"
    for path in LOGIN_PATHS:
        candidates.append(origin + path)

    # de-dup, bound
    uniq = []
    seen = set(tried)
    for c in candidates:
        if c not in seen:
            seen.add(c)
            uniq.append(c)

    pages = 0
    if not evidence:
        for url in uniq:
            if pages >= MAX_PAGES:
                break
            code, chain, text = fetch(session, url)
            if code is None:
                continue
            pages += 1
            hit = scan_text(text, chain)
            if hit:
                evidence = (chain[-1] if chain else url, hit[0], hit[1])
                break

    session.close()
    if evidence:
        return (domain, "YES", evidence[0], evidence[1], evidence[2])
    return (domain, "NO", "", "", "")


def main():
    with open(INFILE) as f:
        domains = [l.strip() for l in f if l.strip()]

    out_yes = open(f"{OUTDIR}/microsoft_sso_domains.txt", "w")
    out_csv = open(f"{OUTDIR}/results.csv", "w", newline="")
    writer = csv.writer(out_csv)
    writer.writerow(["domain", "ms_sso", "evidence_url", "signal_type", "signal"])

    lock = threading.Lock()
    counts = {"done": 0, "yes": 0, "err": 0}
    total = len(domains)
    start = time.time()

    def work(d):
        try:
            return check_domain(d)
        except Exception as e:
            return (d, "ERR", "", "", str(e)[:80])

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for res in ex.map(work, domains):
            if res is None:
                continue
            domain, status, evurl, sigtype, sig = res
            with lock:
                counts["done"] += 1
                if status == "YES":
                    counts["yes"] += 1
                    out_yes.write(domain + "\n")
                    out_yes.flush()
                elif status == "ERR":
                    counts["err"] += 1
                writer.writerow([domain, status, evurl, sigtype, sig])
                out_csv.flush()
                if counts["done"] % 100 == 0:
                    el = time.time() - start
                    rate = counts["done"] / el if el else 0
                    eta = (total - counts["done"]) / rate if rate else 0
                    print(f"{counts['done']}/{total} | yes={counts['yes']} "
                          f"err={counts['err']} | {rate:.1f}/s ETA {eta/60:.1f}m",
                          flush=True)

    out_yes.close()
    out_csv.close()
    el = time.time() - start
    print(f"DONE {counts['done']}/{total} yes={counts['yes']} err={counts['err']} "
          f"in {el/60:.1f}m", flush=True)


if __name__ == "__main__":
    main()
