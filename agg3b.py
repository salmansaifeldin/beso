# aggregator that also includes iso_out.csv
import csv, glob, sys, collections
wd, tag = sys.argv[1], sys.argv[2]
best={}
for fn in glob.glob(f"{wd}/out_*.csv")+[f"{wd}/iso_out.csv"]:
    try:
        for r in csv.reader(open(fn)):
            if not r or r[0]=="domain" or len(r)<5: continue
            best[r[0]]=r
    except: pass
def gg(cats): return sorted(d for d,r in best.items() if r[1] in cats)
def mm(cats): return sorted(d for d,r in best.items() if r[3] in cats)
g_want=gg({"jwt","token"})
g_cand=gg({"jwt_candidate","token_candidate","code_candidate","google_candidate"})
ms_conf=mm({"microsoft"}); ms_cand=mm({"microsoft_candidate"})
open(f"{tag}_google_confirmed.txt","w").write("\n".join(g_want)+("\n" if g_want else ""))
open(f"{tag}_google_candidate.txt","w").write("\n".join(g_cand)+("\n" if g_cand else ""))
open(f"{tag}_ms_confirmed.txt","w").write("\n".join(ms_conf)+("\n" if ms_conf else ""))
open(f"{tag}_ms_candidate.txt","w").write("\n".join(ms_cand)+("\n" if ms_cand else ""))
with open(f"{tag}_results.csv","w",newline="") as f:
    w=csv.writer(f); w.writerow(["domain","g_cat","g_ev","ms_cat","ms_ev","login_url"])
    for d in sorted(best): w.writerow(best[d])
cg=collections.Counter(r[1] for r in best.values()); cm=collections.Counter(r[3] for r in best.values())
print(f"[{tag}] total={len(best)}  Google confirmed(jwt+ya29)={len(g_want)} cand={len(g_cand)} | MS confirmed={len(ms_conf)} cand={len(ms_cand)}  (code={cg.get('code',0)})")
