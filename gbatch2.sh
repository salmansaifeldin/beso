#!/bin/bash
cd /home/user/beso
DUR="${1:-560}"
WD=scan_work_g2
SRCLIST=newlist_5k.txt
mkdir -p "$WD"
export FAST=1
python3 - "$WD" "$SRCLIST" <<'PY'
import csv, glob, os, random, sys
WD, SRC = sys.argv[1], sys.argv[2]
done={}
for fn in [f"{WD}/_master.csv"]+sorted(glob.glob(f"{WD}/out_*.csv")):
    if not os.path.exists(fn): continue
    for row in csv.reader(open(fn)):
        if row and row[0]!="domain" and len(row)>=2: done[row[0]]=row
csv.writer(open(f"{WD}/_master.csv","w",newline="")).writerows(done.values())
alld=[l.strip() for l in open(SRC) if l.strip()]
rem=[d for d in alld if d not in done]
for f in glob.glob(f"{WD}/shard_*.txt")+glob.glob(f"{WD}/out_*.csv")+glob.glob(f"{WD}/log_*.txt"):
    os.remove(f)
random.shuffle(rem)
N=8
fs=[open(f"{WD}/shard_{i}.txt","w") for i in range(N)]
for i,d in enumerate(rem): fs[i%N].write(d+"\n")
for f in fs: f.close()
print(f"start master={len(done)} remaining={len(rem)} total={len(alld)}")
PY
timeout "$DUR" bash -c '
export FAST=1
for i in $(seq 0 7); do
  python3 /home/user/beso/google_scan.py "scan_work_g2/shard_$i.txt" "scan_work_g2/out_$i.csv" >>"scan_work_g2/log_$i.txt" 2>&1 &
done
wait
'
python3 - "$WD" "$SRCLIST" <<'PY'
import csv, glob, os, sys
from collections import Counter
WD, SRC = sys.argv[1], sys.argv[2]
done={}
for fn in [f"{WD}/_master.csv"]+sorted(glob.glob(f"{WD}/out_*.csv")):
    if not os.path.exists(fn): continue
    for row in csv.reader(open(fn)):
        if row and row[0]!="domain" and len(row)>=2: done[row[0]]=row
total=len(open(SRC).read().split())
c=Counter(r[1] for r in done.values()); n=len(done)
print("==== GBATCH2 DONE ====")
print(f"TOTAL={n}/{total}  remaining={total-n}")
print(f"jwt={c.get('jwt',0)} token={c.get('token',0)} code={c.get('code',0)} unknown={c.get('google_unknown',0)} none={c.get('none',0)}")
print(f"WANT(jwt+token)={c.get('jwt',0)+c.get('token',0)}")
PY
