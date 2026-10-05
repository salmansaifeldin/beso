#!/usr/bin/env python3
# aggregate a 3-tier scan_work dir into confirmed/candidate files
import csv, glob, sys
wd, tag = sys.argv[1], sys.argv[2]
best={}
for fn in glob.glob(f"{wd}/out_*.csv"):
    for r in csv.reader(open(fn)):
        if not r or r[0]=="domain" or len(r)<5: continue
        best[r[0]]=r
def gg(cats): return sorted(d for d,r in best.items() if r[1] in cats)
def mm(cats): return sorted(d for d,r in best.items() if r[3] in cats)
g_conf=gg({"jwt","token","code"})
g_conf_want=gg({"jwt","token"})          # WANT = jwt+ya29 only
g_cand=gg({"jwt_candidate","token_candidate","code_candidate","google_candidate"})
ms_conf=mm({"microsoft"})
ms_cand=mm({"microsoft_candidate"})
open(f"{tag}_google_confirmed.txt","w").write("\n".join(g_conf_want)+("\n" if g_conf_want else ""))
open(f"{tag}_google_candidate.txt","w").write("\n".join(g_cand)+("\n" if g_cand else ""))
open(f"{tag}_ms_confirmed.txt","w").write("\n".join(ms_conf)+("\n" if ms_conf else ""))
open(f"{tag}_ms_candidate.txt","w").write("\n".join(ms_cand)+("\n" if ms_cand else ""))
with open(f"{tag}_results.csv","w",newline="") as f:
    w=csv.writer(f); w.writerow(["domain","g_cat","g_ev","ms_cat","ms_ev","login_url"])
    for d in sorted(best): w.writerow(best[d])
import collections
cg=collections.Counter(r[1] for r in best.values()); cm=collections.Counter(r[3] for r in best.values())
print(f"[{tag}] total={len(best)}")
print(f"  Google: jwt={cg.get('jwt',0)} ya29={cg.get('token',0)} code={cg.get('code',0)} | cand: jwt={cg.get('jwt_candidate',0)} token={cg.get('token_candidate',0)} code={cg.get('code_candidate',0)} google={cg.get('google_candidate',0)}")
print(f"  Microsoft: confirmed={cm.get('microsoft',0)} candidate={cm.get('microsoft_candidate',0)}")
print(f"  WANT confirmed (jwt+ya29)={len(g_conf_want)}  Google candidates={len(g_cand)}")
