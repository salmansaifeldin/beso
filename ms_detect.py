#!/usr/bin/env python3
"""
Detect Microsoft SSO on a list of "domain[,url]" lines.
Per domain: load homepage + common login pages, read first-party JS, click any
'...with Microsoft' button, and look for Microsoft identity markers.

Verdict:
  microsoft    -> explicit Microsoft login (login.microsoftonline.com / b2clogin /
                  ciamlogin / login.live.com / MSAL / 'Sign in with Microsoft' button
                  / response to microsoftonline with client_id)
  generic_sso  -> a generic 'SSO / single sign-on' button but no MS marker proven
  none         -> no Microsoft / SSO trace
Output CSV: domain, category, confirmed, evidence, login_url, final_url
"""
import sys, re, csv, glob, os
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

ARGS=["--no-sandbox","--disable-dev-shm-usage","--disable-gpu","--ignore-certificate-errors",
      "--ssl-version-max=tls1.2","--disable-http2",
      "--disable-features=site-per-process,IsolateOrigins,TranslateUI","--mute-audio"]
UA=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
PATHS=["", "login", "signin", "sign-in", "account/login", "auth/login", "users/sign_in"]

MS_HOST=re.compile(r"login\.microsoftonline\.com|login\.microsoftonline\.us|login\.windows\.net|"
                   r"login\.live\.com|[a-z0-9\-]+\.b2clogin\.com|[a-z0-9\-]+\.ciamlogin\.com|"
                   r"login\.partner\.microsoftonline\.cn|sts\.windows\.net", re.I)
MSAL=re.compile(r"msal\.js|msal-browser|@azure/msal|MsalProvider|PublicClientApplication|msal\.min\.js", re.I)
MS_BTN=re.compile(r"(sign ?in|log ?in|continue|connect)[^<>{}]{0,20}with\s+microsoft|"
                  r"microsoft\s+account|sign ?in with azure|with\s+office\s*365|entra\s*id", re.I)
MS_AUTHZ=re.compile(r"microsoftonline\.com/[^\"'\s]*/oauth2/(?:v2\.0/)?authorize[^\"'\s<>\\]*", re.I)
GENERIC_SSO=re.compile(r">\s*(?:use\s+)?(?:single sign.?on|sso)\s*<|sign ?in with sso|continue with sso", re.I)


def classify(blob):
    if MS_HOST.search(blob):
        return "microsoft", "ms_host:"+ (MS_HOST.search(blob).group(0))
    if MS_AUTHZ.search(blob):
        return "microsoft", "ms_authorize"
    if MSAL.search(blob):
        return "microsoft", "msal:"+MSAL.search(blob).group(0)
    if MS_BTN.search(blob):
        return "microsoft", "btn:"+re.sub(r"\s+"," ",MS_BTN.search(blob).group(0))[:40]
    if GENERIC_SSO.search(blob):
        return "generic_sso", "generic_sso"
    return "none", ""


def analyze(browser, domain, url):
    ctx=browser.new_context(ignore_https_errors=True, user_agent=UA, viewport={"width":1280,"height":900})
    ctx.set_default_navigation_timeout(22000); ctx.set_default_timeout(5000)
    chunks=[]; ms_net=[False]; login_url=url; final=""
    def on_req(r):
        if MS_HOST.search(r.url): ms_net[0]=True
    def on_resp(resp):
        try:
            u=resp.url; host=urlparse(u).netloc.lower(); rt=resp.request.resource_type
            if rt not in ("script","fetch","xhr","document"): return
            if any(h in host for h in ("googletagmanager","google-analytics","doubleclick","facebook","hotjar")): return
            if not (u.endswith(".js") or "javascript" in resp.headers.get("content-type","") or rt in("document","script")): return
            if sum(len(c) for c in chunks)>6_000_000: return
            t=resp.text()
            if t and re.search(r"microsoft|msal|b2clogin|ciamlogin|azure|sso|single sign|oauth2",t,re.I):
                chunks.append(t)
        except: pass
    ctx.on("request",on_req); ctx.on("response",on_resp)
    pg=ctx.new_page()
    reached=False
    for pth in PATHS:
        u=f"https://{domain}/{pth}"
        try:
            pg.goto(u, wait_until="domcontentloaded"); pg.wait_for_timeout(2500)
            reached=True; login_url=u; final=pg.url
            try: chunks.append(pg.content())
            except: pass
            blob="\n".join(chunks)
            if MS_HOST.search(blob) or MSAL.search(blob) or MS_BTN.search(blob) or MS_AUTHZ.search(blob) or ms_net[0]:
                break
        except Exception:
            continue
    # try clicking a Microsoft button to fire redirect
    if reached and not ms_net[0]:
        for sel in ["text=/with microsoft/i","text=/microsoft account/i","[class*=microsoft i]","button:has-text('Microsoft')","text=/single sign/i","text=/\\bSSO\\b/"]:
            try:
                loc=pg.locator(sel).first
                if loc.count()>0:
                    loc.click(timeout=2500); pg.wait_for_timeout(2500)
                    try: chunks.append(pg.content())
                    except: pass
                    break
            except: pass
    ctx.close()
    if not reached:
        return [domain,"unreachable","","","",""]
    blob="\n".join(chunks)
    if ms_net[0]:
        return [domain,"microsoft","yes","ms_redirect",login_url,final]
    cat,ev=classify(blob)
    return [domain,cat,"yes" if cat=="microsoft" else "",ev,login_url,final]


def main():
    pairs=[]
    for l in open(sys.argv[1]):
        l=l.strip()
        if not l: continue
        p=l.split(",",1); pairs.append((p[0], p[1] if len(p)>1 else f"https://{p[0]}/"))
    outfile=sys.argv[2]; done=set()
    if os.path.exists(outfile):
        for r in csv.reader(open(outfile)):
            if r and r[0]!="domain": done.add(r[0])
    pairs=[(d,u) for d,u in pairs if d not in done]
    newf=not os.path.exists(outfile)
    out=open(outfile,"a",newline=""); w=csv.writer(out)
    if newf: w.writerow(["domain","category","confirmed","evidence","login_url","final_url"]); out.flush()
    exe=sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))[-1]
    px=os.environ.get("HTTPS_PROXY")
    with sync_playwright() as p:
        def mk(): return p.chromium.launch(headless=True, executable_path=exe, args=ARGS+([f"--proxy-server={px}"] if px else []))
        b=mk(); n=0
        for d,u in pairs:
            try: row=analyze(b,d,u)
            except Exception as e:
                try: b.close()
                except: pass
                b=mk(); row=[d,"err","",str(e)[:30],u,""]
            w.writerow(row); out.flush()
            print(f"{d:28s} {row[1]:12s} {row[3][:40]}",flush=True)
            n+=1
            if n%40==0:
                try: b.close()
                except: pass
                b=mk()
        try: b.close()
        except: pass
    out.close()

if __name__=="__main__": main()
