#!/usr/bin/env python3
"""
Deep resolver for 'gsi_only' domains: open the login page in the browser, read
the body of every JavaScript the page actually loads (including code-split
chunks), and determine which Google Identity Services method the site calls:

  initTokenClient          -> token (ya29 access_token)      [WANT]
  google.accounts.id.*     -> jwt   (id_token credential)    [WANT]
  initCodeClient / code    -> code  (excluded)

Also captures any accounts.google.com response_type as the gold-standard signal.
Input file: lines "domain,login_url". Output CSV like the main scanner.
"""
import sys, re, csv, glob, os
from playwright.sync_api import sync_playwright

LAUNCH_ARGS = [
    "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
    "--ssl-version-max=tls1.2",
    "--disable-blink-features=AutomationControlled",
    "--disable-features=site-per-process,IsolateOrigins,TranslateUI",
    "--mute-audio"]
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

RT = re.compile(r"accounts\.google\.com/o/oauth2/(?:v2/)?auth[^\"'\s<>\\]*", re.I)
INIT_TOKEN = re.compile(r"oauth2\.initTokenClient|\binitTokenClient\b", re.I)
INIT_CODE = re.compile(r"oauth2\.initCodeClient|\binitCodeClient\b", re.I)
GIS_ID = re.compile(r"accounts\.id\.(?:initialize|prompt|renderButton)|g_id_onload|"
                    r"data-client_id|accounts\.google\.com/gsi/(?:iframe/select|status|button)", re.I)
GIS_ANY = re.compile(r"accounts\.google\.com/gsi|google\.accounts\.(?:id|oauth2)|"
                     r"accounts\.google\.com/o/oauth2|apis\.google\.com/js/(?:platform|api)|"
                     r"g_id_onload|data-client_id", re.I)
from urllib.parse import urlparse, parse_qs


def make_browser(p):
    exe = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))
    prox = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
    kw = {"headless": True, "args": LAUNCH_ARGS}
    if exe:
        kw["executable_path"] = exe[-1]
    if prox:
        kw["proxy"] = {"server": prox}
    return p.chromium.launch(**kw)


def classify(js_blob, rtypes):
    toks = set(t for rt in rtypes for t in rt.split())
    if "id_token" in toks:
        return "jwt", "response_type=id_token"
    if "token" in toks:
        return "token", "response_type=token"
    # the site's own GIS call captured from its JS
    if INIT_TOKEN.search(js_blob):
        return "token", "initTokenClient"
    if GIS_ID.search(js_blob) and not INIT_CODE.search(js_blob) and "code" not in toks:
        return "jwt", "gis_id:" + GIS_ID.search(js_blob).group(0)[:26]
    if "code" in toks:
        return "code", "response_type=code"
    if INIT_CODE.search(js_blob):
        return "code", "initCodeClient"
    # distinguish "Google present but flow not captured" from "no Google at all"
    if GIS_ANY.search(js_blob):
        return "google_unknown", "gsi_only"
    return "none", ""


def analyze(browser, domain, login_url):
    ctx = browser.new_context(ignore_https_errors=True, user_agent=UA,
                              viewport={"width": 1280, "height": 900})
    ctx.set_default_navigation_timeout(25000)
    ctx.set_default_timeout(6000)
    rtypes = []
    js_chunks = []
    total = [0]

    def on_req(r):
        u = r.url
        if RT.search(u):
            rt = (parse_qs(urlparse(u.replace("\\/", "/")).query).get("response_type", [""])[0]).lower()
            if rt:
                rtypes.append(rt)

    def on_resp(resp):
        try:
            u = resp.url
            rtype = resp.request.resource_type
            if rtype not in ("script", "fetch", "xhr", "document"):
                return
            # CRITICAL: never read Google-hosted libraries — the gsi/client bundle
            # itself contains all of initTokenClient/initCodeClient/accounts.id, so
            # reading it would falsely match every flow. Only the SITE'S OWN code
            # calls exactly one of them, and that is the real signal.
            host = urlparse(u).netloc.lower()
            if any(h in host for h in ("accounts.google.com", "apis.google.com",
                                        "gstatic.com", "googleapis.com", "google.com/gsi")):
                return
            if not (u.endswith(".js") or "javascript" in (resp.headers.get("content-type", "")) or rtype == "script"):
                return
            if total[0] > 8_000_000:
                return
            body = resp.text()
            if body and ("google" in body.lower() or "gsi" in body.lower() or "oauth" in body.lower()):
                js_chunks.append(body)
                total[0] += len(body)
        except Exception:
            pass

    ctx.on("request", on_req)
    ctx.on("response", on_resp)
    page = ctx.new_page()
    ev = "gsi_only"
    cat = "google_unknown"
    try:
        try:
            page.goto(login_url, wait_until="domcontentloaded")
        except Exception:
            page.goto(f"https://{domain}/login", wait_until="domcontentloaded")
        page.wait_for_timeout(3500)
        # nudge: click a Google button / expander if present, to fire the flow
        for sel in ["text=/continue with google/i", "text=/sign in with google/i",
                    "[aria-label*=Google i]", "[class*=google i]", "button:has-text('Google')"]:
            try:
                loc = page.locator(sel).first
                if loc.count() > 0:
                    loc.click(timeout=2500)
                    page.wait_for_timeout(2500)
                    break
            except Exception:
                pass
        # also trigger a gsi button iframe if present
        try:
            for fr in page.frames:
                if "/gsi/button" in (fr.url or ""):
                    fr.locator("div[role=button], button, [tabindex]").first.click(timeout=2000)
                    page.wait_for_timeout(2000)
                    break
        except Exception:
            pass
        try:
            js_chunks.append(page.content())
        except Exception:
            pass
        cat, ev = classify("\n".join(js_chunks), rtypes)
    except Exception as e:
        ev = "ERR:" + str(e)[:30]
    finally:
        try:
            ctx.close()
        except Exception:
            pass
    conf = "yes" if cat in ("jwt", "token") else ""
    return [domain, cat, conf, ev, login_url, ""]


def main():
    pairs = []
    for l in open(sys.argv[1]):
        l = l.strip()
        if not l:
            continue
        parts = l.split(",", 1)
        pairs.append((parts[0], parts[1] if len(parts) > 1 else f"https://{parts[0]}/login"))
    outfile = sys.argv[2]
    done = set()
    if os.path.exists(outfile):
        for r in csv.reader(open(outfile)):
            if r and r[0] != "domain":
                done.add(r[0])
    pairs = [(d, u) for d, u in pairs if d not in done]
    newfile = not os.path.exists(outfile)
    out = open(outfile, "a", newline="")
    w = csv.writer(out)
    if newfile:
        w.writerow(["domain", "category", "confirmed", "evidence", "login_url", "final_url"])
        out.flush()
    with sync_playwright() as p:
        b = make_browser(p)
        for i, (d, lu) in enumerate(pairs):
            try:
                row = analyze(b, d, lu)
            except Exception as e:
                try:
                    b.close()
                except Exception:
                    pass
                b = make_browser(p)
                row = [d, "google_unknown", "", "ERR2:" + str(e)[:30], lu, ""]
            w.writerow(row); out.flush()
            print(f"{d:22s} {row[1]:15s} {row[3]}", flush=True)
        try:
            b.close()
        except Exception:
            pass
    out.close()


if __name__ == "__main__":
    main()
