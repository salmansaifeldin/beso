#!/bin/bash
cd /home/user/beso
DUR="${1:-560}"; WD=scan_work_u; SRC=newg.txt
mkdir -p "$WD"; export FAST=1
python3 - <<'PY'
import csv, glob, os, random
WD="scan_work_u"
done={}
for fn in [f"{WD}/_master.csv"]+sorted(glob.glob(f"{WD}/out_*.csv")):
    if not os.path.exists(fn): continue
    for row in csv.reader(open(fn)):
        if row and row[0]!="domain" and len(row)>=2: done[row[0]]=row
csv.writer(open(f"{WD}/_master.csv","w",newline="")).writerows(done.values())
alld=[l.strip() for l in open("newg.txt") if l.strip()]
rem=[d for d in alld if d not in done]
for f in glob.glob(f"{WD}/shard_*.txt")+glob.glob(f"{WD}/out_*.csv")+glob.glob(f"{WD}/log_*.txt"):
    os.remove(f)
random.shuffle(rem)
N=8
fs=[open(f"{WD}/shard_{i}.txt","w") for i in range(N)]
for i,d in enumerate(rem): fs[i%N].write(d+"\n")
for f in fs: f.close()
print(f"start master={len(done)} remaining={len(rem)}")
PY
timeout "$DUR" bash -c '
export FAST=1
for i in $(seq 0 7); do
  python3 /home/user/beso/google_scan.py "scan_work_u/shard_$i.txt" "scan_work_u/out_$i.csv" >>"scan_work_u/log_$i.txt" 2>&1 &
done
wait
'
python3 - <<'PY'
import csv, glob, os
from collections import Counter
WD="scan_work_u"; done={}
for fn in [f"{WD}/_master.csv"]+sorted(glob.glob(f"{WD}/out_*.csv")):
    if not os.path.exists(fn): continue
    for row in csv.reader(open(fn)):
        if row and row[0]!="domain" and len(row)>=2: done[row[0]]=row
c=Counter(r[1] for r in done.values()); tot=len(done)
print("==== UBATCH DONE ====")
print(f"TOTAL={tot}/251 remaining={251-tot}")
print(f"jwt={c.get('jwt',0)} token={c.get('token',0)} code={c.get('code',0)} unknown={c.get('google_unknown',0)} none={c.get('none',0)}")
print(f"WANT(jwt+ya29)={c.get('jwt',0)+c.get('token',0)}")
PY
