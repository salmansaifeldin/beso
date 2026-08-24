#!/bin/bash
cd /home/user/beso
DUR="${1:-560}"; WD=scan_work_r; SRC=urls_pairs.txt
mkdir -p "$WD"; export FAST=1
python3 - "$WD" "$SRC" <<'PY'
import csv, glob, os, sys
WD,SRC=sys.argv[1],sys.argv[2]
done=set()
for fn in glob.glob(f"{WD}/out_*.csv"):
    for r in csv.reader(open(fn)):
        if r and r[0]!="domain": done.add(r[0])
rem=[l.strip() for l in open(SRC) if l.strip() and l.split(",",1)[0] not in done]
for f in glob.glob(f"{WD}/shard_*.txt"): os.remove(f)
N=8
fs=[open(f"{WD}/shard_{i}.txt","w") for i in range(N)]
for i,d in enumerate(rem): fs[i%N].write(d+"\n")
for f in fs: f.close()
print(f"remaining={len(rem)}")
PY
timeout "$DUR" bash -c '
export FAST=1
for i in $(seq 0 7); do
  python3 /home/user/beso/resolve_gsi.py "scan_work_r/shard_$i.txt" "scan_work_r/out_$i.csv" >>"scan_work_r/log_$i.txt" 2>&1 &
done
wait
'
python3 - <<'PY'
import csv, glob, os
from collections import Counter
done={}
for fn in sorted(glob.glob("scan_work_r/out_*.csv")):
    for r in csv.reader(open(fn)):
        if r and r[0]!="domain" and len(r)>=2: done[r[0]]=r
c=Counter(r[1] for r in done.values())
print("==== RBATCH ===="); print(f"done={len(done)}/79")
print(f"jwt={c.get('jwt',0)} token={c.get('token',0)} code={c.get('code',0)} unknown={c.get('google_unknown',0)} none={c.get('none',0)}")
print(f"WANT(jwt+ya29)={c.get('jwt',0)+c.get('token',0)}")
PY
