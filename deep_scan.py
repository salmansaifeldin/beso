#!/usr/bin/env python3
"""
Deep combined Google + Microsoft SSO scanner for BARE domains.
Per domain: try many login paths, wait, read all first-party JS, click the
Google/Microsoft buttons, capture OAuth requests. One browser visit covers both.

Output CSV: domain, g_cat, g_ev, ms_cat, ms_ev, login_url
  g_cat : jwt | token | code | google_unknown | none
  ms_cat: microsoft | none
"""
import sys, re, csv, glob, os
from urllib.parse import urlparse, parse_qs
from playwright.sync_api import sync_playwright

ARGS=["--no-sandbox","--disable-dev-shm-usage","--disable-gpu","--ignore-certificate-errors",
      "--ssl-version-max=tls1.2","--disable-http2",
      "--disable-blink-features=AutomationControlled",
      "--disable-features=site-per-process,IsolateOrigins,TranslateUI","--mute-audio"]
UA=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
PATHS=["", "login", "signin", "sign-in", "sign-up", "account/login", "users/sign_in",
       "auth/login", "app/login", "en/login", "register", "account/signin"]

RT=re.compile(r"accounts\.google\.com/o/oauth2/(?:v2/)?auth[^\"'\s<>\\]*", re.I)
INIT_TOKEN=re.compile(r"oauth2\.initTokenClient|\binitTokenClient\b", re.I)
INIT_CODE=re.compile(r"oauth2\.initCodeClient|\binitCodeClient\b", re.I)
GIS_ID=re.compile(r"accounts\.id\.(?:initialize|prompt|renderButton)|g_id_onload|data-client_id|"
                  r"accounts\.google\.com/gsi/(?:iframe/select|status|button)", re.I)
GIS_ANY=re.compile(r"accounts\.google\.com/gsi|google\.accounts\.(?:id|oauth2)|"
                   r"accounts\.google\.com/o/oauth2|g_id_onload|data-client_id", re.I)
MS_HOST=re.compile(r"login\.microsoftonline\.com|login\.microsoftonline\.us|login\.windows\.net|"
                   r"login\.live\.com|[a-z0-9\-]+\.b2clogin\.com|[a-z0-9\-]+\.ciamlogin\.com|sts\.windows\.net", re.I)
MSAL=re.compile(r"msal\.js|msal-browser|@azure/msal|PublicClientApplication|msal\.min\.js", re.I)
MS_BTN=re.compile(r"(sign ?in|log ?in|continue|connect)[^<>{}]{0,20}with\s+microsoft|microsoft\s+account|"
                  r"sign ?in with azure|with\s+office\s*365|entra\s*id", re.I)
MS_AUTHZ=re.compile(r"microsoftonline\.com/[^\"'\s]*/oauth2/(?:v2\.0/)?authorize", re.I)


def g_classify(js, rtypes):
    toks=set(t for rt in rtypes for t in rt.split())
    if "id_token" in toks: return "jwt","response_type=id_token"
    if "token" in toks: return "token","response_type=token"
    if INIT_TOKEN.search(js): return "token","initTokenClient"
    if GIS_ID.search(js) and not INIT_CODE.search(js) and "code" not in toks:
        return "jwt","gis_id:"+GIS_ID.search(js).group(0)[:24]
    if "code" in toks: return "code","response_type=code"
    if INIT_CODE.search(js): return "code","initCodeClient"
    if GIS_ANY.search(js): return "google_unknown","gsi_only"
    return "none",""


def ms_classify(blob):
    if MS_HOST.search(blob): return "microsoft","ms_host:"+MS_HOST.search(blob).group(0)[:30]
    if MS_AUTHZ.search(blob): return "microsoft","ms_authorize"
    if MSAL.search(blob): return "microsoft","msal"
    if MS_BTN.search(blob): return "microsoft","btn:"+re.sub(r"\s+"," ",MS_BTN.search(blob).group(0))[:34]
    return "none",""


LOGIN_LINK=re.compile(r"(log[\s\-]?in|sign[\s\-]?in|sign[\s\-]?up|/account|/auth|/users/sign|get[\s\-]?started|register|anmelden|connexion|conta)", re.I)

def analyze(browser, domain):
    ctx=browser.new_context(ignore_https_errors=True, user_agent=UA, viewport={"width":1280,"height":900})
    ctx.set_default_navigation_timeout(11000); ctx.set_default_timeout(4500)
    rtypes=[]; js=[]; ms_net=[False]; total=[0]
    def on_req(r):
        u=r.url
        if RT.search(u):
            rt=(parse_qs(urlparse(u.replace("\\/","/")).query).get("response_type",[""])[0]).lower()
            if rt: rtypes.append(rt)
        if MS_HOST.search(u): ms_net[0]=True
    def on_resp(resp):
        try:
            u=resp.url; host=urlparse(u).netloc.lower(); rtype=resp.request.resource_type
            if rtype not in ("script","fetch","xhr","document"): return
            if any(h in host for h in ("accounts.google.com","apis.google.com","gstatic.com","googleapis.com")): return
            if not (u.endswith(".js") or "javascript" in resp.headers.get("content-type","") or rtype in("script","document")): return
            if total[0]>9_000_000: return
            b=resp.text()
            if b and re.search(r"google|gsi|oauth|microsoft|msal|b2clogin|azure|sso",b,re.I):
                js.append(b); total[0]+=len(b)
        except: pass
    ctx.on("request",on_req); ctx.on("response",on_resp)
    pg=ctx.new_page()
    used=""; reached=False
    def cur_blob(): return "\n".join(js)
    def strong():
        g,_=g_classify(cur_blob(),rtypes)
        return g in ("jwt","token") or ms_net[0]
    def click_sso():
        for sel in ["text=/continue with google/i","text=/sign in with google/i","[aria-label*=Google i]",
                    "button:has-text('Google')","text=/with microsoft/i","[aria-label*=Microsoft i]","button:has-text('Microsoft')"]:
            try:
                loc=pg.locator(sel).first
                if loc.count()>0:
                    loc.click(timeout=1800); pg.wait_for_timeout(1600)
                    try: js.append(pg.content())
                    except: pass
            except: pass

    import time as _t
    deadline=_t.time()+26   # hard per-domain wall-clock budget
    # 1) homepage first; discover real login links
    cands=[]
    try:
        pg.goto(f"https://{domain}/", wait_until="domcontentloaded"); pg.wait_for_timeout(2500)
        reached=True; used=f"https://{domain}/"
        try: js.append(pg.content())
        except: pass
        try:
            hrefs=pg.eval_on_selector_all("a[href]","els=>els.map(e=>e.getAttribute('href')).filter(Boolean).slice(0,400)")
        except: hrefs=[]
        for h in hrefs:
            if LOGIN_LINK.search(h or ""):
                full=h if h.startswith("http") else f"https://{domain}/"+h.lstrip("/")
                if urlparse(full).netloc.endswith(domain.split('.',1)[-1]) or domain in full:
                    if full not in cands: cands.append(full)
        click_sso()
    except Exception:
        pass
    # candidate login urls: discovered (max 3) + a few common defaults
    probe=[c for c in cands[:3]]
    for p in ["login","signin","sign-in","account/login","users/sign_in"]:
        u=f"https://{domain}/{p}"
        if u not in probe: probe.append(u)
    # 2) probe login candidates, early-exit on strong signal
    if not strong():
        for u in probe[:4]:
            if _t.time()>deadline: break
            try:
                pg.goto(u, wait_until="domcontentloaded"); pg.wait_for_timeout(2500)
                reached=True
                try: js.append(pg.content())
                except: pass
                click_sso()
                if strong(): break
                # if page shows any auth marker, it's a real login page; one extra probe max then stop
                if GIS_ANY.search(cur_blob()) or MS_HOST.search(cur_blob()) or MS_BTN.search(cur_blob()) or MSAL.search(cur_blob()):
                    pass
            except Exception:
                continue
    ctx.close()
    if not reached:
        return [domain,"unreachable","","unreachable","",""]
    gcat,gev=g_classify(cur_blob(),rtypes)
    if ms_net[0]: mscat,msev=("microsoft","ms_redirect")
    else: mscat,msev=ms_classify(cur_blob())
    return [domain,gcat,gev,mscat,msev,used]


def main():
    doms=[l.strip().split(",")[0] for l in open(sys.argv[1]) if l.strip()]
    outfile=sys.argv[2]; done=set()
    if os.path.exists(outfile):
        for r in csv.reader(open(outfile)):
            if r and r[0]!="domain": done.add(r[0])
    doms=[d for d in doms if d not in done]
    newf=not os.path.exists(outfile)
    out=open(outfile,"a",newline=""); w=csv.writer(out)
    if newf: w.writerow(["domain","g_cat","g_ev","ms_cat","ms_ev","login_url"]); out.flush()
    exe=sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))[-1]
    px=os.environ.get("HTTPS_PROXY")
    with sync_playwright() as p:
        def mk(): return p.chromium.launch(headless=True, executable_path=exe, args=ARGS+([f"--proxy-server={px}"] if px else []))
        b=mk(); n=0
        for d in doms:
            try: row=analyze(b,d)
            except Exception as e:
                try: b.close()
                except: pass
                b=mk(); row=[d,"err","","none","",str(e)[:25]]
            w.writerow(row); out.flush()
            print(f"{d:26s} G:{row[1]:14s} MS:{row[3]}",flush=True)
            n+=1
            if n%35==0:
                try: b.close()
                except: pass
                b=mk()
        try: b.close()
        except: pass
    out.close()

if __name__=="__main__": main()
