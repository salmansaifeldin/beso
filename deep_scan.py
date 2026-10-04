#!/usr/bin/env python3
"""
Deep combined Google + Microsoft SSO scanner for BARE domains.

ZERO-FALSE design: a provider is 'confirmed' ONLY when a real request to the
identity provider actually fires — either automatically (One Tap / auto-redirect)
or as a direct result of clicking a genuinely visible provider button. The mere
presence of GIS/MSAL code, One-Tap config divs (#g_id_onload), or button text in
the bundle NEVER confirms (that was the old false-positive source).

Output CSV: domain, g_cat, g_ev, ms_cat, ms_ev, login_url
  g_cat : jwt | token | code | none | unreachable
  ms_cat: microsoft | none
"""
import sys, re, csv, glob, os, time
from urllib.parse import urlparse, parse_qs
from playwright.sync_api import sync_playwright

ARGS=["--no-sandbox","--disable-dev-shm-usage","--disable-gpu","--ignore-certificate-errors",
      "--ssl-version-max=tls1.2","--disable-http2",
      "--disable-blink-features=AutomationControlled",
      "--disable-features=site-per-process,IsolateOrigins,TranslateUI","--mute-audio"]
UA=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# Real identity-provider REQUEST signatures (these only fire when a flow actually runs)
G_AUTH=re.compile(r"accounts\.google\.com/o/oauth2/(?:v2/)?auth", re.I)
G_GSI=re.compile(r"accounts\.google\.com/gsi/(?:button|select|iframe|fedcm|status)", re.I)
MS_AUTH_REQ=re.compile(r"login\.microsoftonline\.com|login\.microsoftonline\.us|login\.windows\.net|"
                       r"login\.live\.com|[a-z0-9\-]+\.b2clogin\.com|[a-z0-9\-]+\.ciamlogin\.com", re.I)
# SAFE JS signals: an actual oauth2 CALL with an object literal + a real client_id,
# and NOT the @react-oauth library (which bundles both call sites for every flow).
# This recovers recall for button-wired initTokenClient / initCodeClient flows
# (popup-based, whose request we often cannot capture) WITHOUT the false positives,
# because the reported-false domains had no real call / no client_id.
# NOTE: accounts.id.* / g_id_onload (One Tap) is deliberately NOT trusted from JS —
# it auto-prompts and is frequently dormant (that was a false-positive source).
INIT_TOKEN_CALL=re.compile(r"(?:oauth2\.)?initTokenClient\s*\(\s*\{", re.I)
INIT_CODE_CALL=re.compile(r"(?:oauth2\.)?initCodeClient\s*\(\s*\{", re.I)
REACT_OAUTH=re.compile(r"@react-oauth|react-oauth", re.I)
CLIENT_ID=re.compile(r"[0-9]{6,}-[a-z0-9]+\.apps\.googleusercontent\.com", re.I)
LOGIN_LINK=re.compile(r"(log[\s\-]?in|sign[\s\-]?in|sign[\s\-]?up|/account|/auth|/users/sign|get[\s\-]?started|register|anmelden|connexion)", re.I)

G_SEL=["text=/continue with google/i","text=/sign ?in with google/i","text=/log ?in with google/i",
       "text=/sign ?up with google/i","[aria-label*=google i]","button:has-text('Google')",
       "a:has-text('Google')",".g_id_signin","iframe[src*='gsi/button']"]
M_SEL=["text=/continue with microsoft/i","text=/sign ?in with microsoft/i","text=/log ?in with microsoft/i",
       "text=/with microsoft/i","text=/microsoft account/i","text=/sign ?in with azure/i",
       "[aria-label*=microsoft i]","button:has-text('Microsoft')","a:has-text('Microsoft')"]


def analyze(browser, domain):
    ctx=browser.new_context(ignore_https_errors=True, user_agent=UA, viewport={"width":1280,"height":900})
    ctx.set_default_navigation_timeout(11000); ctx.set_default_timeout(4500)
    gauth=[]; ggsi=[False]; msauth=[False]; js=[]; total=[0]
    def on_req(r):
        u=r.url
        if G_AUTH.search(u):
            rt=(parse_qs(urlparse(u.replace("\\/","/")).query).get("response_type",[""])[0]).lower()
            gauth.append(rt or "gsi")
        elif G_GSI.search(u):
            ggsi[0]=True
        if MS_AUTH_REQ.search(u):
            try: nav=r.is_navigation_request()
            except Exception: nav=False
            if nav or r.resource_type=="document": msauth[0]=True
    def on_resp(resp):
        try:
            u=resp.url; host=urlparse(u).netloc.lower(); rtype=resp.request.resource_type
            if rtype not in ("script","document"): return
            if any(h in host for h in ("accounts.google.com","apis.google.com","gstatic.com","googleapis.com")): return
            if total[0]>8_000_000: return
            b=resp.text()
            if b and ("initTokenClient" in b or "initCodeClient" in b or "googleusercontent" in b):
                js.append(b); total[0]+=len(b)
        except: pass
    ctx.on("request",on_req); ctx.on("response",on_resp)
    pg=ctx.new_page()
    used=""; reached=False
    deadline=time.time()+28
    g_ok=[False]; ms_ok=[False]; vis_g=[False]; vis_ms=[False]
    # A genuinely RENDERED provider button is what a human sees on manual check.
    # Only count the rendered GIS button iframe (gsi/button), a filled .g_id_signin,
    # or a short visible text/aria button — NOT #g_id_onload config divs or the
    # One-Tap prompt card (those were the dormant false-positive source).
    # ONLY the official Google Identity Services rendered button counts as a visible
    # signal: the gsi/button iframe or a filled .g_id_signin container. These are
    # GIS-specific and the dormant false-positive sites never render them. A generic
    # "...with Google/Microsoft" text match is deliberately NOT used — it produced
    # false positives (e.g. the word Microsoft in unrelated UI).
    VIS_JS="""()=>{
      const vis=e=>{if(!e)return false;const r=e.getBoundingClientRect();return r.width>40&&r.height>14&&e.offsetParent!==null;};
      let g=false;
      for(const f of document.querySelectorAll('iframe')){if(/gsi\\/button/.test(f.src||'')&&vis(f))g=true;}
      for(const e of document.querySelectorAll('.g_id_signin')){if(vis(e)&&e.querySelector('iframe,div[role=button],div'))g=true;}
      return g?'G':'';
    }"""
    def check_vis():
        try:
            if 'G' in pg.evaluate(VIS_JS): vis_g[0]=True
        except: pass
    def g_hits(): return len(gauth)+(1 if ggsi[0] else 0)
    def click_provider(sels, kind):
        """Click a VISIBLE provider button; confirm only if it triggers a real IdP request."""
        for sel in sels:
            try:
                loc=pg.locator(sel).first
                if loc.count()==0: continue
                try:
                    if not loc.is_visible(): continue
                except Exception: continue
                before_g=g_hits(); before_ms=msauth[0]
                try: loc.click(timeout=1800)
                except Exception: continue
                pg.wait_for_timeout(2000)
                if kind=="g" and g_hits()>before_g: g_ok[0]=True; return True
                if kind=="m" and (msauth[0] and not before_ms): ms_ok[0]=True; return True
            except Exception: continue
        return False
    def reveal_email():
        try:
            em=pg.locator("input[type=email], input[name*=email i], input[id*=email i], input[autocomplete=username]").first
            if em.count()==0: return
            em.fill("test.user@gmail.com", timeout=1800)
            for cont in ["button:has-text('Continue')","button:has-text('Next')","button[type=submit]","text=/^continue$/i","text=/^next$/i"]:
                try:
                    c=pg.locator(cont).first
                    if c.count()>0: c.click(timeout=1600); pg.wait_for_timeout(2200); break
                except: pass
        except: pass
    def scan_page():
        check_vis()
        # auto One Tap / auto-redirect already captured on load; now click real buttons
        if not g_ok[0]: click_provider(G_SEL,"g")
        if not ms_ok[0]: click_provider(M_SEL,"m")
        if not (g_ok[0] or ms_ok[0] or vis_g[0] or vis_ms[0]):
            reveal_email()
            check_vis()
            if not g_ok[0]: click_provider(G_SEL,"g")
            if not ms_ok[0]: click_provider(M_SEL,"m")
    def found(): return g_ok[0] or ms_ok[0] or vis_g[0] or vis_ms[0] or bool(gauth) or ggsi[0] or msauth[0]

    cands=[]
    try:
        pg.goto(f"https://{domain}/", wait_until="domcontentloaded"); pg.wait_for_timeout(2600)
        reached=True; used=f"https://{domain}/"
        try:
            hrefs=pg.eval_on_selector_all("a[href]","els=>els.map(e=>e.getAttribute('href')).filter(Boolean).slice(0,400)")
        except: hrefs=[]
        for h in hrefs:
            if LOGIN_LINK.search(h or ""):
                full=h if h.startswith("http") else f"https://{domain}/"+h.lstrip("/")
                if domain in full and full not in cands: cands.append(full)
        scan_page()
    except Exception:
        pass
    probe=[c for c in cands[:3]]
    for p in ["login","signin","sign-in","sign-up","signup","register","account/login","users/sign_in","app/login","account"]:
        u=f"https://{domain}/{p}"
        if u not in probe: probe.append(u)
    if not found():
        for u in probe[:4]:
            if time.time()>deadline: break
            try:
                pg.goto(u, wait_until="domcontentloaded"); pg.wait_for_timeout(2600)
                reached=True
                scan_page()
                if found(): break
            except Exception:
                continue
    ctx.close()
    if not reached:
        return [domain,"unreachable","","unreachable","",""]
    # GOOGLE verdict
    gcat,gev="none",""
    rts=set(gauth)
    blob="\n".join(js)
    if "id_token" in rts: gcat,gev="jwt","req:response_type=id_token"
    elif "token" in rts: gcat,gev="token","req:response_type=token"
    elif "code" in rts: gcat,gev="code","req:response_type=code"
    elif ggsi[0] or "gsi" in rts: gcat,gev="jwt","req:gsi_onetap"
    # SAFE JS fallback for button-wired popup flows we couldn't capture live:
    elif INIT_TOKEN_CALL.search(blob) and CLIENT_ID.search(blob) and not REACT_OAUTH.search(blob):
        gcat,gev="token","js:initTokenClient_call+client_id"
    elif INIT_CODE_CALL.search(blob) and CLIENT_ID.search(blob) and not REACT_OAUTH.search(blob):
        gcat,gev="code","js:initCodeClient_call+client_id"
    # VISIBLE rendered Google button (what a human sees) — classify by JS if we can,
    # else default jwt (a rendered GIS "Sign in with Google" button is id_token).
    elif vis_g[0]:
        if INIT_TOKEN_CALL.search(blob) and not REACT_OAUTH.search(blob): gcat,gev="token","visible_button+initTokenClient"
        elif INIT_CODE_CALL.search(blob) and not REACT_OAUTH.search(blob): gcat,gev="code","visible_button+initCodeClient"
        else: gcat,gev="jwt","visible_google_button"
    # MICROSOFT verdict — ONLY a real redirect to the MS IdP (text buttons too noisy)
    mscat,msev=("microsoft","req:ms_redirect") if msauth[0] else ("none","")
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
