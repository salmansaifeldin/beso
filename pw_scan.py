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
import sys, re, csv, time, os, signal
from playwright.sync_api import sync_playwright

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


def analyze(browser, domain, verbose=False):
    ev = {"domain": domain, "category": "none", "confirmed": "",
          "evidence": "", "login_url": "", "final_url": ""}
    ctx = browser.new_context(ignore_https_errors=True, user_agent=UA,
                              viewport={"width": 1280, "height": 900})
    ctx.set_default_navigation_timeout(22000)
    ctx.set_default_timeout(8000)
    try:
        ctx.add_init_script("Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
                            "window.chrome={runtime:{}};")
    except Exception:
        pass
    net = []
    try:
        ctx.route("**/*", lambda r: (r.abort() if r.request.resource_type in
                  ("image", "media", "font") else r.continue_()))
    except Exception:
        pass

    def reach(url, page):
        try:
            page.goto(url, wait_until="domcontentloaded")
            page.wait_for_timeout(2500)
            return True
        except Exception:
            return False

    page = ctx.new_page()
    page.on("request", lambda r: net.append(r.url))
    try:
        # 1. homepage -> discover login link
        login_url = None
        for base in (f"https://{domain}/", f"https://www.{domain}/", f"http://{domain}/"):
            if reach(base, page):
                login_url = get_login_url(page, domain)
                break
        # 2. candidate login urls
        cands = []
        if login_url:
            cands.append(login_url)
        cands += [f"https://{domain}/login", f"https://{domain}/signin",
                  f"https://app.{domain}/login", f"https://accounts.{domain}/login",
                  f"https://login.{domain}/", f"https://secure.{domain}/login",
                  f"https://my.{domain}/login"]
        seen = set()
        reached_login = False
        for cu in cands:
            if cu in seen:
                continue
            seen.add(cu)
            net.clear()
            if not reach(cu, page):
                continue
            ev["login_url"] = cu
            ev["final_url"] = page.url
            # quick: does this look like a login page or did we already pass?
            ms, sso = scan(page, net)
            reached_login = True
            if ms:
                ev["category"] = "microsoft"; ev["evidence"] = ms
                break
            # try expanders
            for _ in range(3):
                clicked = False
                try:
                    els = page.query_selector_all(AUTH_SEL)
                except Exception:
                    els = []
                for el in els[:60]:
                    lab = label_of(el).lower()
                    if lab and len(lab) < 40 and EXPAND_RE.search(lab) and not MS_EXCLUDE.search(lab):
                        try:
                            el.click(timeout=3000); page.wait_for_timeout(1500); clicked = True
                        except Exception:
                            pass
                        break
                ms, sso2 = scan(page, net)
                sso = sso or sso2
                if ms:
                    ev["category"] = "microsoft"; ev["evidence"] = ms
                    break
                if not clicked:
                    break
            if ev["category"] == "microsoft":
                break
            # email-first probe
            if not ms:
                try:
                    email = page.query_selector("input[type=email], input[name*=email i], input[id*=email i], input[autocomplete=username]")
                    pwd = page.query_selector("input[type=password]")
                    if email and not pwd:
                        email.fill("john.smith@example.com")
                        # click a continue/next button
                        for el in page.query_selector_all("button, [role=button], input[type=submit]")[:40]:
                            lab = label_of(el).lower()
                            if re.search(r"continue|next|sign\s*in|log\s*in|submit", lab) and len(lab) < 30:
                                try:
                                    el.click(timeout=3000); break
                                except Exception:
                                    pass
                        page.wait_for_timeout(2500)
                        ms, sso2 = scan(page, net)
                        sso = sso or sso2
                        if ms:
                            ev["category"] = "microsoft"; ev["evidence"] = ms
                except Exception:
                    pass
            if ev["category"] == "microsoft":
                break
            if sso and ev["category"] == "none":
                ev["category"] = "generic_sso"; ev["evidence"] = sso
                # keep scanning other candidates only if we want microsoft; stop—generic found
                break
            if reached_login:
                break  # we found a real login page; don't keep probing subdomains
        # 3. confirm microsoft button by clicking (if not net-confirmed)
        if ev["category"] == "microsoft" and not ev["evidence"].startswith("net:"):
            btn = find_ms_button(page)
            if btn:
                net.clear()
                try:
                    with ctx.expect_page(timeout=6000) as pop:
                        btn.click(timeout=4000)
                    np = pop.value
                    np.wait_for_timeout(3000)
                    allurls = net + [np.url]
                    if any(MS_AUTH_HOSTS.search(u) for u in allurls):
                        ev["confirmed"] = "yes"
                except Exception:
                    try:
                        btn.click(timeout=3000); page.wait_for_timeout(3500)
                        if any(MS_AUTH_HOSTS.search(u) for u in net) or MS_AUTH_HOSTS.search(page.url):
                            ev["confirmed"] = "yes"
                    except Exception:
                        pass
        elif ev["evidence"].startswith("net:"):
            ev["confirmed"] = "yes"
    except Exception as e:
        ev["evidence"] = "ERR:" + str(e)[:40]
    finally:
        try:
            ctx.close()
        except Exception:
            pass
    if verbose:
        print(f"{domain:32s} {ev['category']:11s} conf={ev['confirmed']:3s} {ev['evidence']:45s} {ev['login_url']}", flush=True)
    return ev


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
        browser = p.chromium.launch(headless=True, args=[
            "--no-sandbox", "--disable-dev-shm-usage",
            "--disable-blink-features=AutomationControlled"])
        with open(outfile, "a", newline="") as out:
            w = csv.writer(out)
            if newfile:
                w.writerow(["domain", "category", "confirmed", "evidence", "login_url", "final_url"])
                out.flush()
            for i, d in enumerate(todo):
                ev = analyze(browser, d, verbose=verbose)
                w.writerow([ev["domain"], ev["category"], ev["confirmed"],
                            ev["evidence"], ev["login_url"], ev["final_url"]])
                out.flush()
        browser.close()


if __name__ == "__main__":
    main()
