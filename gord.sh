#!/bin/bash
cd /home/user/beso
DUR="${1:-560}"; WIN="${2:-4000}"
WD=scan_work_g2; SRC=newlist_ordered_remaining.txt
python3 - "$WD" "$SRC" "$WIN" <<'PY'
import csv, glob, os, sys
WD, SRC, WIN = sys.argv[1], sys.argv[2], int(sys.argv[3])
done={}
for fn in [f"{WD}/_master.csv"]+sorted(glob.glob(f"{WD}/out_*.csv"))+[f"{WD}/tail_out.csv"]:
    if not os.path.exists(fn): continue
    for r in csv.reader(open(fn)):
        if r and r[0]!="domain" and len(r)>=2: done[r[0]]=r
csv.writer(open(f"{WD}/_master.csv","w",newline="")).writerows(done.values())
# next WIN unscanned domains IN ORDER (recognizable first)
rem=[]
for l in open(SRC):
    d=l.strip()
    if d and d not in done:
        rem.append(d)
        if len(rem)>=WIN: break
for f in glob.glob(f"{WD}/shard_*.txt")+glob.glob(f"{WD}/out_*.csv")+glob.glob(f"{WD}/log_*.txt"):
    os.remove(f)
N=8
fs=[open(f"{WD}/shard_{i}.txt","w") for i in range(N)]
for i,d in enumerate(rem): fs[i%N].write(d+"\n")   # round-robin keeps order within shard
for f in fs: f.close()
print(f"master(done)={len(done)} this_window={len(rem)}")
PY
timeout "$DUR" bash -c '
export FAST=1
for i in $(seq 0 7); do
  python3 /home/user/beso/google_scan.py "scan_work_g2/shard_$i.txt" "scan_work_g2/out_$i.csv" >>"scan_work_g2/log_$i.txt" 2>&1 &
done
wait
'
python3 - "$WD" <<'PY'
import csv, glob, os, sys
from collections import Counter
WD=sys.argv[1]; done={}
for fn in [f"{WD}/_master.csv"]+sorted(glob.glob(f"{WD}/out_*.csv"))+[f"{WD}/tail_out.csv"]:
    if not os.path.exists(fn): continue
    for r in csv.reader(open(fn)):
        if r and r[0]!="domain" and len(r)>=2: done[r[0]]=r
c=Counter(r[1] for r in done.values())
print("==== GORD DONE ====")
print(f"new-list total scanned={len(done)}")
print(f"jwt={c.get('jwt',0)} token={c.get('token',0)} code={c.get('code',0)} unknown={c.get('google_unknown',0)} none={c.get('none',0)}")
print(f"WANT(jwt+token)={c.get('jwt',0)+c.get('token',0)}")
PY
