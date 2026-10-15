#!/usr/bin/env python3
"""For a given domain already known to use Microsoft SSO, follow the real
redirect to login.microsoftonline.com (or b2clogin/ciamlogin/login.live.com)
and classify Microsoft's response_type:
  code     = standard auth-code flow (NO JWT to client)
  id_token = JWT (OpenID Connect implicit)  ← what the user wants
  id_token_token = JWT + access_token (hybrid implicit)
  token    = access_token only (rare, deprecated)
  none     = SSO exists but no MS request fired within budget
"""
import sys, re, glob, time
from urllib.parse import urlparse, parse_qs, unquote
from playwright.sync_api import sync_playwright

ARGS=["--no-sandbox","--disable-dev-shm-usage","--disable-gpu","--ignore-certificate-errors",
      "--ssl-version-max=tls1.2","--disable-http2","--disable-blink-features=AutomationControlled",
      "--disable-features=site-per-process,IsolateOrigins,TranslateUI","--mute-audio"]
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
exe=sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))[-1]

MS_HOST=re.compile(r"login\.microsoftonline\.com|login\.microsoftonline\.us|login\.windows\.net|login\.live\.com|[a-z0-9\-]+\.b2clogin\.com|[a-z0-9\-]+\.ciamlogin\.com", re.I)
MS_SEL=["text=/continue with microsoft/i","text=/sign ?in with microsoft/i","text=/log ?in with microsoft/i",
        "text=/with microsoft/i","text=/microsoft account/i","text=/sign ?in with azure/i",
        "[aria-label*=microsoft i]","button:has-text('Microsoft')","a:has-text('Microsoft')",
        "button:has-text('SSO')","[data-provider*=microsoft i]","[data-provider*=azure i]"]
PATHS=["","/","login","signin","sign-in","account/login","users/sign_in","sign-up","signup",
       "auth/login","account","dashboard"]
SUBS=["app","login","my","account","secure","dashboard","portal","console","admin"]

def classify_rt(rt):
    if not rt: return "none"
    rt=rt.lower().strip()
    if "id_token" in rt and "token" in rt and "id_token" != rt: return "id_token_token"
    if "id_token" in rt: return "id_token"
    if rt=="token": return "token"
    if rt=="code": return "code"
    return rt

def scan(dom, deadline):
    ms_reqs=[]
    def onreq(r):
        if MS_HOST.search(r.url): ms_reqs.append(r.url)
    with sync_playwright() as p:
        br=p.chromium.launch(executable_path=exe,args=ARGS,headless=True)
        ctx=br.new_context(ignore_https_errors=True,user_agent=UA,viewport={"width":1280,"height":900})
        ctx.set_default_navigation_timeout(10000); ctx.set_default_timeout(4500)
        ctx.on("request",onreq); ctx.on("page",lambda pg:pg.on("request",onreq))
        pg=ctx.new_page(); pg.on("request",onreq)
        tried=[f"https://{dom}/{p}" for p in PATHS[:6]]+[f"https://{s}.{dom}/login" for s in SUBS[:4]]
        for url in tried:
            if time.time()>deadline or ms_reqs: break
            try: pg.goto(url,wait_until="domcontentloaded",timeout=9000); pg.wait_for_timeout(1800)
            except Exception: continue
            # click MS button
            for sel in MS_SEL:
                if time.time()>deadline or ms_reqs: break
                try:
                    for el in pg.query_selector_all(sel)[:3]:
                        if el.is_visible():
                            try:
                                with ctx.expect_page(timeout=3500) as pop: el.click(timeout=2200)
                                try: pop.value.wait_for_timeout(1800)
                                except: pass
                            except Exception:
                                try: el.click(timeout=2200); pg.wait_for_timeout(1800)
                                except: pass
                            break
                except Exception: pass
            # email reveal (identifier-first forms)
            if not ms_reqs:
                try:
                    inp=pg.query_selector("input[type=email], input[name*=email i], input[id*=email i], input[name=username], input[autocomplete=username]")
                    if inp and inp.is_visible():
                        inp.fill("test.user@contoso.onmicrosoft.com"); pg.wait_for_timeout(400)
                        for s in ["button:has-text('Continue')","button:has-text('Next')","button:has-text('Sign In')","button[type=submit]"]:
                            b=pg.query_selector(s)
                            if b and b.is_visible():
                                try: b.click(timeout=2500); pg.wait_for_timeout(2500)
                                except: pass
                                break
                except: pass
        br.close()
    best="none"; sample=""; client_id=""
    rank={"id_token_token":5,"id_token":4,"token":3,"code":2,"none":1}
    for u in ms_reqs:
        q=parse_qs(urlparse(u).query)
        rt=classify_rt(q.get("response_type",[""])[0])
        if rank.get(rt,0) > rank.get(best,0):
            best=rt
            sample=u[:260]
            client_id=q.get("client_id",[""])[0]
    return best, sample, client_id

def main():
    doms=[l.strip().split(",")[0] for l in open(sys.argv[1]) if l.strip() and not l.startswith("#")]
    out=sys.argv[2]
    import os
    done=set()
    if os.path.exists(out):
        for l in open(out):
            if l.startswith("domain,"): continue
            done.add(l.split(",")[0])
    doms=[d for d in doms if d not in done]
    with open(out,"a",buffering=1) as f:
        if os.stat(out).st_size==0: f.write("domain,ms_type,client_id,sample\n")
        for d in doms:
            try:
                deadline=time.time()+42
                t,s,cid=scan(d,deadline)
            except Exception as e:
                t,s,cid="error",f"{type(e).__name__}",""
            # csv-safe
            s=s.replace(",","%2C"); cid=cid.replace(",","%2C")
            f.write(f"{d},{t},{cid},{s}\n")
            print(f"{d:34s} {t:14s} {cid[:50]}",flush=True)

if __name__=="__main__": main()
