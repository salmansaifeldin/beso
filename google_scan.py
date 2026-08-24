#!/usr/bin/env python3
"""
Headless-browser detector for Microsoft SSO / generic SSO at a domain's login.

For each domain:
  1. Find the login page (follow a login link from the homepage, else probe
     common paths/subdomains).
  2. Render it; collect network requests, DOM, visible text, and auth-button
     labels.
  3. Expand hidden options ("Continue with SSO", "more options", email-first)
     to reveal additional providers.
  4. If a Microsoft button is found, click it to confirm a redirect to
     login.microsoftonline.com (gold-standard).

Classification:
  microsoft   -> explicit "Sign in with Microsoft" button, MS auth redirect,
                 or "with Microsoft" text.
  generic_sso -> a generic SSO/SAML option (no labelled Microsoft button).
  none        -> neither found.
"""
import sys, re, csv, time, os, signal, socket, threading
from playwright.sync_api import sync_playwright

_resolve_cache = {}


def resolves(host):
    """DNS check with a hard 5s timeout so a hung getaddrinfo can never
    stall a worker. Cached. Runs the lookup in a daemon thread; if it does
    not finish in time we treat the host as unresolved and move on."""
    if host in _resolve_cache:
        return _resolve_cache[host]
    result = {"ok": False}

    def _lookup():
        try:
            socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
            result["ok"] = True
        except Exception:
            result["ok"] = False

    t = threading.Thread(target=_lookup, daemon=True)
    t.start()
    t.join(5.0)
    ok = result["ok"] if not t.is_alive() else False
    _resolve_cache[host] = ok
    return ok

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

MS_AUTH_HOSTS = re.compile(
    r"login\.microsoftonline\.com|login\.microsoftonline\.us|"
    r"login\.partner\.microsoftonline\.cn|login\.microsoft\.com|"
    r"login\.windows\.net|sts\.windows\.net|login\.live\.com|"
    r"\bmsftauth\.net\b|\bmsauth\.net\b|aadcdn\.msftauth", re.I)

# explicit Microsoft sign-in button / text
MS_BTN_RE = re.compile(
    r"(sign\s*in|sign\s*up|log\s*in|login|continue|connect|use)\s*"
    r"(with|using|via)?\s*(microsoft|azure\s*ad|azure\s*active|"
    r"office\s*365|microsoft\s*365|entra)\b", re.I)
MS_BARE_RE = re.compile(r"^\s*(microsoft|microsoft\s*365|azure\s*ad|"
                        r"office\s*365|microsoft\s*entra|entra\s*id)\s*$", re.I)
MS_TEXT_RE = re.compile(
    r"(sign\s*in|sign\s*up|log\s*in|login|continue|connect)\s*"
    r"(with|using|via)\s*(microsoft|azure\s*ad|office\s*365|"
    r"microsoft\s*365|entra)\b", re.I)
MS_CONFIG_RE = re.compile(r"login\.microsoftonline|\bentraid\b|"
                          r"\bmicrosoft_?entra\b|azureactivedirectory", re.I)

# generic SSO
SSO_RE = re.compile(r"\bsso\b|single\s*sign[\s-]*on|\bsaml\b|"
                    r"enterprise\s*(login|sign|sso)|use\s*sso|"
                    r"continue\s*with\s*sso|sign\s*in\s*with\s*sso", re.I)

# things that look like Microsoft but are NOT an SSO button
MS_EXCLUDE = re.compile(r"corporation|advertis|clarity|teams|integrat|"
                        r"powered\s*by|partner|store|download|edge|"
                        r"copyright|cookie|consent|outlook\.com\s*calendar|"
                        r"office\s*add", re.I)

# expanders to click to reveal hidden providers
EXPAND_RE = re.compile(r"more\s*option|other\s*ways|single\s*sign|use\s*sso|"
                       r"continue\s*with\s*sso|enterprise|work\s*email|"
                       r"\bsso\b|show\s*more|all\s*sign", re.I)

# login-link discovery on homepage
LOGIN_LINK_RE = re.compile(r"log\s*in|login|sign\s*in|signin|sign\s*up|"
                           r"my\s*account|get\s*started|portal|console|"
                           r"dashboard|workspace", re.I)
LOGIN_HREF_RE = re.compile(r"log[\s_-]?in|sign[\s_-]?in|sign[\s_-]?up|"
                           r"/account|/auth|/sso|/users/sign", re.I)
# avoid non-app login links (training portals, docs, blog, etc.)
LOGIN_HREF_SKIP = re.compile(r"/training|/learn|/blog|/docs|/support|/community|"
                             r"/careers|/pricing|/contact|/events|/partners|"
                             r"/resources|/help|/news|/academy|/certif", re.I)

AUTH_SEL = "button, a, [role=button], input[type=submit], input[type=button], div[tabindex]"

# third-party analytics/ads/video hosts that burn CPU but never gate a login
# form. (Deliberately NOT blocking recaptcha, consent, or CSS, which some
# login pages need to render their provider buttons.)
BLOCK_HOSTS = re.compile(
    r"google-analytics|googletagmanager|doubleclick|googlesyndication|"
    r"facebook\.com/tr|connect\.facebook|"
    r"hotjar|fullstory|mouseflow|mixpanel|"
    r"criteo|taboola|outbrain|adroll|quantserve|"
    r"scorecardresearch|youtube\.com|ytimg|vimeo|wistia|"
    r"tiktok|snapchat|pinterest|ads-twitter", re.I)

BLOCK_TYPES = ("image", "media", "font")


def _route(route):
    try:
        req = route.request
        if req.resource_type in BLOCK_TYPES or BLOCK_HOSTS.search(req.url):
            return route.abort()
        return route.continue_()
    except Exception:
        try:
            return route.continue_()
        except Exception:
            return


def label_of(el):
    try:
        parts = [el.inner_text() or ""]
    except Exception:
        parts = [""]
    for a in ("aria-label", "title", "value", "alt", "data-provider"):
        try:
            v = el.get_attribute(a)
            if v:
                parts.append(v)
        except Exception:
            pass
    return " ".join(parts).strip().replace("\n", " ")


def scan(page, net):
    """Return (ms_evidence|None, sso_evidence|None)."""
    ms = sso = None
    for u in net:
        if MS_AUTH_HOSTS.search(u):
            return ("net:" + MS_AUTH_HOSTS.search(u).group(0), None)
    try:
        html = page.content()
    except Exception:
        html = ""
    if MS_CONFIG_RE.search(html):
        ms = "cfg:" + MS_CONFIG_RE.search(html).group(0)[:30]
    try:
        itxt = page.inner_text("body")
    except Exception:
        itxt = ""
    m = MS_TEXT_RE.search(itxt)
    if m:
        ms = "txt:" + m.group(0)[:40]
    # auth elements
    try:
        els = page.query_selector_all(AUTH_SEL)
    except Exception:
        els = []
    for el in els[:120]:
        lab = label_of(el)
        if not lab or len(lab) > 60:
            continue
        low = lab.lower()
        if (MS_BTN_RE.search(low) or MS_BARE_RE.search(low)) and not MS_EXCLUDE.search(low):
            ms = "btn:" + lab[:40]
            break
    if not sso:
        m2 = SSO_RE.search(itxt)
        if m2:
            sso = "txt:" + m2.group(0)[:30]
        else:
            for el in els[:120]:
                lab = label_of(el)
                if lab and len(lab) < 50 and SSO_RE.search(lab.lower()):
                    sso = "btn:" + lab[:30]
                    break
    return (ms, sso)


def find_ms_button(page):
    try:
        els = page.query_selector_all(AUTH_SEL)
    except Exception:
        return None
    for el in els[:120]:
        lab = label_of(el)
        low = lab.lower()
        if not lab or len(lab) > 60:
            continue
        if (MS_BTN_RE.search(low) or MS_BARE_RE.search(low)) and not MS_EXCLUDE.search(low):
            return el
    return None


def get_login_url(page, domain):
    """From homepage, return best login URL (or None)."""
    best = None
    try:
        els = page.query_selector_all("a, button, [role=button]")
    except Exception:
        els = []
    for el in els[:200]:
        try:
            txt = (el.inner_text() or "").strip()
            href = el.get_attribute("href") or ""
        except Exception:
            continue
        if href and LOGIN_HREF_RE.search(href) and not LOGIN_HREF_SKIP.search(href):
            best = href
            if LOGIN_LINK_RE.search(txt):
                return href
        elif txt and re.fullmatch(r"\s*(log\s*in|login|sign\s*in|sign in)\s*", txt, re.I) and href:
            return href
    return best


GOOGLE_AUTH_RE = re.compile(r"accounts\.google\.com/o/oauth2/(?:v2/)?auth", re.I)
GSI_RE = re.compile(r"accounts\.google\.com/gsi/", re.I)
GSI_CRED_RE = re.compile(r"accounts\.google\.com/gsi/(?:iframe/select|status|button)", re.I)
GOOGLE_BTN_RE = re.compile(r"\bgoogle\b", re.I)
GOOGLE_BTN_EXCLUDE = re.compile(
    r"recaptcha|gtag|analytics|tagmanager|tag\s*manager|gstatic|fonts|"
    r"maps|google\s*play|play\s*store|translate|adsense|\bads\b|doubleclick|"
    r"pay|wallet|cloud\s*platform|workspace\s*marketplace|review|rating", re.I)


def parse_response_type(url):
    try:
        from urllib.parse import urlparse, parse_qs
        return (parse_qs(urlparse(url).query).get("response_type", [""])[0]).lower()
    except Exception:
        return ""


def classify_google(goog_urls, html, extra_href=""):
    """Decide the Google login flow type from captured OAuth/GSI traffic.
    Returns (category, evidence). Categories:
      jwt   -> id_token JWT returned to the app (WANT)
      token -> access_token ya29 returned to the app (WANT)
      code  -> only an auth code returned (EXCLUDE)
      google_unknown -> Google present, flow not captured
      none  -> no Google login
    """
    rtypes = []
    for u in list(goog_urls) + ([extra_href] if extra_href else []):
        if GOOGLE_AUTH_RE.search(u):
            rt = parse_response_type(u)
            if rt:
                rtypes.append(rt)
    toks = set()
    for rt in rtypes:
        toks.update(rt.split())
    # token-returning response types win (access_token or id_token in the callback)
    if "id_token" in toks:
        return "jwt", "response_type=" + ";".join(sorted(set(rtypes)))
    if "token" in toks:
        return "token", "response_type=" + ";".join(sorted(set(rtypes)))
    # GIS "Sign in with Google" credential = id_token JWT posted to the app
    gis_cred = any(GSI_CRED_RE.search(u) for u in goog_urls) or \
        bool(re.search(r"g_id_onload|google\.accounts\.id\b", html or "", re.I))
    if gis_cred and "code" not in toks:
        return "jwt", "gis_credential"
    if "code" in toks:
        return "code", "response_type=" + ";".join(sorted(set(rtypes)))
    if any(GSI_RE.search(u) for u in goog_urls) or re.search(r"google\.accounts\.oauth2", html or "", re.I):
        return "google_unknown", "gsi_only"
    return "none", ""


def find_google_button(page):
    try:
        els = page.query_selector_all("button, a, [role=button], [class*=google i], [id*=google i], [data-provider*=google i]")
    except Exception:
        return None, ""
    for el in els[:140]:
        try:
            lab = ((el.inner_text() or "") + " " + (el.get_attribute("aria-label") or "") + " "
                   + (el.get_attribute("title") or "") + " " + (el.get_attribute("class") or "")
                   + " " + (el.get_attribute("data-provider") or ""))
        except Exception:
            continue
        if GOOGLE_BTN_RE.search(lab) and len(lab.strip()) < 70 and not GOOGLE_BTN_EXCLUDE.search(lab):
            href = ""
            try:
                href = el.get_attribute("href") or ""
            except Exception:
                pass
            return el, href
    return None, ""


def analyze(browser, domain, verbose=False):
    ev = {"domain": domain, "category": "none", "confirmed": "",
          "evidence": "", "login_url": "", "final_url": ""}
    ctx = browser.new_context(ignore_https_errors=True, user_agent=UA,
                              viewport={"width": 1280, "height": 900})
    ctx.set_default_navigation_timeout(13000)
    ctx.set_default_timeout(4000)
    try:
        ctx.add_init_script("Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
                            "window.chrome={runtime:{}};")
    except Exception:
        pass
    net = []
    goog = []  # accounts.google.com URLs captured across all pages/popups

    def on_req(r):
        u = r.url
        net.append(u)
        if "accounts.google.com" in u:
            goog.append(u)
    ctx.on("request", on_req)
    try:
        ctx.route("**/*", _route)
    except Exception:
        pass

    def reach(url, page, wait=1600):
        try:
            page.goto(url, wait_until="domcontentloaded")
            page.wait_for_timeout(wait)
            return True
        except Exception:
            return False

    page = ctx.new_page()
    try:
        # 0. DNS gate
        apex_ok = resolves(domain)
        www_ok = resolves("www." + domain)
        if not apex_ok and not www_ok:
            ev["evidence"] = "ERR:dns"
            try:
                ctx.close()
            except Exception:
                pass
            if verbose:
                print(f"{domain:30s} none  ERR:dns", flush=True)
            return ev
        # 1. homepage -> discover login link
        login_url = None
        bases = []
        if apex_ok:
            bases.append(f"https://{domain}/")
        if www_ok:
            bases.append(f"https://www.{domain}/")
        if apex_ok:
            bases.append(f"http://{domain}/")
        for base in bases:
            if reach(base, page):
                login_url = get_login_url(page, domain)
                break
        # 2. candidate login urls
        cands = []
        if login_url:
            cands.append(login_url)
        cands += [f"https://{domain}/login", f"https://{domain}/signin"]
        for sub in ("app", "accounts", "login", "secure", "my"):
            host = f"{sub}.{domain}"
            if resolves(host):
                cands.append(f"https://{host}/login")
        seen = set()
        for cu in cands:
            if cu in seen:
                continue
            seen.add(cu)
            if not reach(cu, page, wait=(2200 if os.environ.get("FAST") == "1" else 2800)):
                continue
            ev["login_url"] = cu
            ev["final_url"] = page.url
            page.wait_for_timeout(1400)  # let GIS scripts initialise
            try:
                html = page.content()
            except Exception:
                html = ""
            # GIS credential signal in the DOM
            try:
                if page.query_selector("#g_id_onload, [id^=g_id], .g_id_signin, div[data-client_id], div[data-onsuccess]"):
                    html += " g_id_onload"
            except Exception:
                pass
            # trigger the GIS button iframe (cross-origin) to fire the credential flow
            try:
                for fr in page.frames:
                    if "/gsi/button" in (fr.url or ""):
                        try:
                            fr.locator("div[role=button], button, [tabindex]").first.click(timeout=2000)
                            page.wait_for_timeout(1800)
                        except Exception:
                            pass
                        break
            except Exception:
                pass

            def current():
                return classify_google(goog, html)

            cat, evd = current()
            # try to reveal a hidden Google button via expanders
            if cat in ("none", "google_unknown"):
                for _ in range(2):
                    btn, href = find_google_button(page)
                    if btn is None:
                        # click an expander/SSO control to reveal providers
                        clicked = False
                        try:
                            els = page.query_selector_all(AUTH_SEL)
                        except Exception:
                            els = []
                        for el in els[:60]:
                            lab = label_of(el).lower()
                            if lab and len(lab) < 40 and EXPAND_RE.search(lab):
                                try:
                                    el.click(timeout=2500); page.wait_for_timeout(1200); clicked = True
                                except Exception:
                                    pass
                                break
                        if not clicked:
                            break
                        continue
                    break
            # if we have a classic Google button, use its href or click it
            btn, href = find_google_button(page)
            if href and GOOGLE_AUTH_RE.search(href):
                try:
                    html2 = page.content()
                except Exception:
                    html2 = html
                cat, evd = classify_google(goog, html2, extra_href=href)
            elif btn is not None and classify_google(goog, html)[0] in ("none", "google_unknown"):
                # click to trigger the OAuth request and capture response_type
                before = len(goog)
                try:
                    with ctx.expect_page(timeout=5000) as pop:
                        btn.click(timeout=3500)
                    pop.value.wait_for_timeout(2500)
                except Exception:
                    try:
                        btn.click(timeout=3000); page.wait_for_timeout(2500)
                    except Exception:
                        pass
                try:
                    html3 = page.content()
                except Exception:
                    html3 = html
                cat, evd = classify_google(goog, html3)
            else:
                cat, evd = current()
            ev["category"] = cat
            ev["evidence"] = evd
            if cat in ("jwt", "token"):
                ev["confirmed"] = "yes"
            break  # processed the (first) real login page
    except Exception as e:
        ev["evidence"] = "ERR:" + str(e)[:40]
    finally:
        try:
            ctx.close()
        except Exception:
            pass
    if verbose:
        print(f"{domain:30s} {ev['category']:15s} {ev['evidence'][:50]:50s} {ev['login_url']}", flush=True)
    return ev



LAUNCH_ARGS = [
    "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
    # Some egress proxies reset Chromium's TLS 1.3 ClientHello; cap at TLS 1.2
    # so navigations succeed through a MITM proxy (harmless when direct).
    "--ssl-version-max=tls1.2",
    "--disable-blink-features=AutomationControlled",
    "--disable-features=site-per-process,IsolateOrigins,TranslateUI,BackForwardCache",
    "--disable-extensions", "--mute-audio",
    "--disable-background-timer-throttling",
    "--disable-renderer-backgrounding",
    "--disable-backgrounding-occluded-windows"]

RECYCLE_EVERY = 40  # relaunch the browser periodically to avoid memory bloat


import glob as _glob


def _chromium_path():
    # Prefer an explicit override, else use the pre-installed browser bundle.
    envp = os.environ.get("CHROMIUM_BIN")
    if envp and os.path.exists(envp):
        return envp
    for pat in ("/opt/pw-browsers/chromium-*/chrome-linux/chrome",
                "/opt/pw-browsers/chromium/chrome-linux/chrome"):
        hits = sorted(_glob.glob(pat))
        if hits:
            return hits[-1]
    return None


def make_browser(p):
    exe = _chromium_path()
    kw = {"headless": True, "args": LAUNCH_ARGS}
    if exe:
        kw["executable_path"] = exe
    # Route Chromium through the environment's outbound proxy if one is set,
    # otherwise external navigations get ERR_CONNECTION_RESET.
    prox = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
    if prox:
        kw["proxy"] = {"server": prox}
    return p.chromium.launch(**kw)


def main():
    infile = sys.argv[1]
    outfile = sys.argv[2] if len(sys.argv) > 2 else "pw_results.csv"
    verbose = "-v" in sys.argv
    with open(infile) as f:
        domains = [l.strip() for l in f if l.strip()]
    done = set()
    if os.path.exists(outfile):
        with open(outfile) as f:
            for row in csv.reader(f):
                if row:
                    done.add(row[0])
    todo = [d for d in domains if d not in done]
    newfile = not os.path.exists(outfile)

    with sync_playwright() as p:
        browser = make_browser(p)
        since = 0
        with open(outfile, "a", newline="") as out:
            w = csv.writer(out)
            if newfile:
                w.writerow(["domain", "category", "confirmed", "evidence", "login_url", "final_url"])
                out.flush()
            for d in todo:
                # periodic recycle to bound memory
                if since >= RECYCLE_EVERY:
                    try:
                        browser.close()
                    except Exception:
                        pass
                    browser = make_browser(p)
                    since = 0
                try:
                    ev = analyze(browser, d, verbose=verbose)
                except Exception as e:
                    # browser/context likely died: relaunch and retry once
                    try:
                        browser.close()
                    except Exception:
                        pass
                    try:
                        browser = make_browser(p)
                        since = 0
                        ev = analyze(browser, d, verbose=verbose)
                    except Exception as e2:
                        ev = {"domain": d, "category": "none", "confirmed": "",
                              "evidence": "ERR2:" + str(e2)[:40], "login_url": "",
                              "final_url": ""}
                since += 1
                w.writerow([ev["domain"], ev["category"], ev["confirmed"],
                            ev["evidence"], ev["login_url"], ev["final_url"]])
                out.flush()
        try:
            browser.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
