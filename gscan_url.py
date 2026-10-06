#!/usr/bin/env python3
"""Google-SSO-only scanner for EXACT login URLs.
Classifies the Google token returned TO THE CLIENT:
  jwt   = id_token credential (GIS One Tap / response_type=id_token)
  ya29  = access token (response_type=token / initTokenClient)
  code  = Google auth-code flow (EXCLUDED target, reported separately)
  jwt_candidate/ya29_candidate = Google wiring present but no live request captured
  none  = no Google
Confirmation requires a REAL accounts.google.com request (auto or via clicking a
visible Google button), never mere library presence.
"""
import sys, re, glob, json
from urllib.parse import urlparse, parse_qs, unquote
from playwright.sync_api import sync_playwright

ARGS=["--no-sandbox","--disable-dev-shm-usage","--disable-gpu","--ignore-certificate-errors",
      "--ssl-version-max=tls1.2","--disable-http2","--disable-blink-features=AutomationControlled",
      "--disable-features=site-per-process,IsolateOrigins,TranslateUI","--mute-audio"]
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
exe=sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))[-1]

GREQ=re.compile(r"accounts\.google\.com/o/oauth2/(?:v2/)?auth|accounts\.google\.com/gsi/(?:button|select|iframe|fedcm)",re.I)
INIT_TOKEN=re.compile(r"(?:oauth2\.)?initTokenClient\s*\(\s*\{",re.I)
INIT_CODE=re.compile(r"(?:oauth2\.)?initCodeClient\s*\(\s*\{",re.I)
GIS_ID=re.compile(r"accounts\.id\.(?:initialize|renderButton|prompt)|g_id_onload|data-client_id",re.I)
REACT_OAUTH=re.compile(r"@react-oauth|react-oauth",re.I)
CID=re.compile(r"[0-9]{6,}-[a-z0-9]+\.apps\.googleusercontent\.com",re.I)

def reg(h):
    h=h.lower().split("/")[0].split(":")[0]; p=h.split(".")
    return h if len(p)<=2 else ".".join(p[-2:])

def scan(url):
    greq=[]; js=[]
    def on_req(r):
        if GREQ.search(r.url): greq.append(r.url)
    def on_resp(resp):
        try:
            if resp.request.resource_type not in ("script","document"): return
            h=urlparse(resp.url).netloc.lower()
            if any(x in h for x in ("accounts.google.com","gstatic.com","apis.google.com")): return
            b=resp.text()
            if b and re.search(r"initTokenClient|initCodeClient|googleusercontent|accounts\.id\.|g_id_onload|data-client_id",b,re.I):
                js.append(b)
        except: pass
    with sync_playwright() as p:
        br=p.chromium.launch(executable_path=exe,args=ARGS,headless=True)
        ctx=br.new_context(ignore_https_errors=True,user_agent=UA,viewport={"width":1280,"height":900})
        ctx.set_default_navigation_timeout(15000); ctx.set_default_timeout=5000
        ctx.on("request",on_req); ctx.on("response",on_resp)
        ctx.on("page",lambda pg:pg.on("request",on_req))
        pg=ctx.new_page(); pg.on("request",on_req)
        reached=False
        try:
            pg.goto(url,wait_until="domcontentloaded",timeout=15000); reached=True
        except Exception:
            try: pg.goto(url,wait_until="commit",timeout=12000); reached=True
            except Exception: pass
        if reached:
            try: pg.wait_for_timeout(3000)
            except: pass
            # click google button
            def try_click():
                for sel in ["text=/continue with google/i","text=/sign ?in with google/i","text=/log ?in with google/i",
                            "text=/sign ?up with google/i","text=/with google/i","[aria-label*=google i]",
                            "button:has-text('Google')","a:has-text('Google')","[data-provider*=google i]",
                            "[data-connection*=google i]","iframe[src*='gsi/button']",".g_id_signin iframe"]:
                    if greq: return
                    try:
                        for el in pg.query_selector_all(sel):
                            if el.is_visible():
                                try:
                                    with ctx.expect_page(timeout=3500) as pop: el.click(timeout=2500)
                                    pop.value.wait_for_timeout(2000)
                                except Exception:
                                    try: el.click(timeout=2500); pg.wait_for_timeout(2000)
                                    except: pass
                                return
                    except Exception: pass
            try_click()
            # email-first reveal
            if not greq:
                try:
                    inp=pg.query_selector("input[type=email], input[name*=email i], input[id*=email i], input[name=username], input[type=text]")
                    if inp and inp.is_visible():
                        inp.fill("alex.taylor2024@gmail.com"); pg.wait_for_timeout(400)
                        for s in ["button:has-text('Continue')","button:has-text('Next')","button:has-text('Sign In')","button:has-text('Log In')","button:has-text('Login')","button[type=submit]"]:
                            b=pg.query_selector(s)
                            if b and b.is_visible(): 
                                try: b.click(timeout=2500)
                                except: pass
                                break
                        pg.wait_for_timeout(3000); try_click()
                except Exception: pass
        br.close()
    alljs="\n".join(js)
    cid=""
    m=CID.search(alljs)
    if m: cid=m.group(0)
    # classify from captured requests
    rts=set()
    gsi_btn=False
    for u in greq:
        if "/gsi/" in u: gsi_btn=True
        q=parse_qs(urlparse(u.replace("\\/","/")).query)
        rt=q.get("response_type",[""])[0].lower()
        if rt: rts.add(rt)
        if not cid:
            c=q.get("client_id",[""])[0]
            if "googleusercontent" in c: cid=c
    if "id_token" in rts: return ("jwt","req:id_token",cid,reached)
    if "token" in rts and "code" not in rts: return ("ya29","req:token",cid,reached)
    if "token" in rts: return ("ya29","req:token",cid,reached)
    if gsi_btn: return ("jwt","req:gsi_button",cid,reached)
    if "code" in rts: return ("code","req:code(excluded)",cid,reached)
    # JS fallback (candidate only)
    has_react=bool(REACT_OAUTH.search(alljs))
    if INIT_TOKEN.search(alljs) and cid and not has_react: return ("ya29_candidate","js:initTokenClient+cid",cid,reached)
    if GIS_ID.search(alljs) and cid: return ("jwt_candidate","js:gis+cid",cid,reached)
    if INIT_TOKEN.search(alljs): return ("ya29_candidate","js:initTokenClient",cid,reached)
    if GIS_ID.search(alljs): return ("jwt_candidate","js:gis_wire",cid,reached)
    if INIT_CODE.search(alljs) and cid and not has_react: return ("code","js:initCodeClient(excluded)",cid,reached)
    return ("none","" if reached else "unreachable",cid,reached)

if __name__=="__main__":
    url=sys.argv[1]; out=sys.argv[2]
    try:
        cat,ev,cid,reached=scan(url)
    except Exception as e:
        cat,ev,cid,reached="error",type(e).__name__,"",False
    dom=reg(urlparse(url).netloc)
    with open(out,"a") as f:
        f.write(f"{dom}\t{cat}\t{ev}\t{cid}\t{url}\n")
    print(f"{dom:30s} {cat:16s} {ev}")
