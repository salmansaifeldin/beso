#!/usr/bin/env python3
"""Oracle E-Business Suite endpoint prober.
Phase controlled by argv: 
  phase1 <hosts_file> <out_candidates>  -> one quick OA_HTML check per host
  phase2 <cand_file> <out_csv>          -> full 11-endpoint test on candidates
A hit = HTTP 200/302 whose response carries Oracle EBS markers (never a bare 200).
"""
import sys, re, csv, concurrent.futures as cf, warnings
import requests
warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()

ENDPOINTS=[
"/OA_HTML/ibeCAcpSSOReg.jsp","/OA_HTML/jtfwrepo.xml","/OA_HTML/configurator/UiServlet",
"/OA_HTML/ibytransmit","/OA_HTML/OA.jsp","/OA_HTML/RF.jsp","/OA_HTML/BneUploaderService",
"/OA_HTML/BneViewerXMLService","/OA_HTML/BneDownloadService","/OA_HTML/BneOfflineLOVService",
"/OA_HTML/AppsLocalLogin.jsp"]
PHASE1_EP=["/OA_HTML/AppsLocalLogin.jsp","/OA_HTML/OA.jsp","/OA_HTML/RF.jsp"]

# NON-reflectable Oracle EBS body fingerprints: tokens that genuine EBS pages emit
# but a page merely echoing the requested URL/path CANNOT contain (the request path
# only carries OA_HTML / AppsLocalLogin.jsp / jtfwrepo / ibeCAcp / Bne*Service /
# configurator, so those are excluded here to kill path-reflection false positives).
MARK=re.compile(r"Oracle E-Business|E-Business Suite|/OA_MEDIA/|oracle\.apps\.|"
                r"oracle\.jsp\.fnd|FndCommonMessages|oracle\.cabo|OraLogoutRedirect|"
                r"Copyright \(c\)[^<]{0,40}Oracle|Oracle Applications|APPS_SSO|"
                r"GUEST/ORACLE|<!-- Oracle|oabanner|OraBannerText|xmlns:jtf|"
                r"FNDSSCORP|oracle\.cabo\.ui|/OA_HTML/cabo/|AppsLocalLogin.*Oracle", re.I)
# EBS login redirect carries these query params; a bare path-echo redirect does not.
EBS_LOGIN_REDIR=re.compile(r"AppsLocalLogin\.jsp\?.*(requestUrl|cancelUrl|langCode|OAHP|ssousername)", re.I)
UA={"User-Agent":"Mozilla/5.0 (compatible; recon/1.0)"}

def probe(url, req_path):
    try:
        r=requests.get(url,timeout=7,verify=False,allow_redirects=True,headers=UA,stream=True)
        loc=r.headers.get("Location","")
        try: body=r.raw.read(40000,decode_content=True).decode("utf-8","ignore")
        except Exception:
            try: body=r.text[:40000]
            except Exception: body=""
        oracle=bool(MARK.search(body))
        # a redirect chain that lands on a real EBS login (with EBS params) counts
        final=r.url or ""
        if EBS_LOGIN_REDIR.search(final) or EBS_LOGIN_REDIR.search(loc): oracle=True
        return r.status_code, oracle, final[:160]
    except Exception:
        return None, False, ""

def phase1(host):
    """Candidate ONLY if a genuine Oracle EBS marker appears. No bare 'alive'."""
    dead_both=True
    for ep in PHASE1_EP:
        for scheme in ("https","http"):
            st,orc,loc=probe(f"{scheme}://{host}{ep}", ep)
            if st is not None: dead_both=False
            if orc: return (host, ep, loc)
    return None

def main():
    phase=sys.argv[1]; inf=sys.argv[2]; outf=sys.argv[3]
    hosts=[l.strip() for l in open(inf) if l.strip()]
    if phase=="phase1":
        import os
        done=set()
        if os.path.exists(outf):
            for l in open(outf): done.add(l.split("\t")[0])
        hosts=[h for h in hosts if h not in done]
        with open(outf,"a",buffering=1) as f, cf.ThreadPoolExecutor(max_workers=120) as ex:
            for res in ex.map(phase1, hosts):
                if res: f.write(f"{res[0]}\t{res[1]}\t{res[2]}\n")
    else: # phase2
        w=csv.writer(open(outf,"a",buffering=1))
        def test(host):
            hits=[]
            for ep in ENDPOINTS:
                for scheme in ("https","http"):
                    st,orc,loc=probe(f"{scheme}://{host}{ep}", ep)
                    if st is None:
                        if scheme=="http": break
                        continue
                    if orc:  # genuine Oracle EBS response on this endpoint
                        hits.append((ep,scheme,st,loc)); break
                    break
            return host,hits
        with cf.ThreadPoolExecutor(max_workers=60) as ex:
            for host,hits in ex.map(test, hosts):
                for ep,scheme,st,loc in hits:
                    w.writerow([host,ep,scheme,st,loc])
if __name__=="__main__": main()
