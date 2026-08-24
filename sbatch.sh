#!/bin/bash
cd /home/user/beso
DUR="${1:-560}"; WD="${2:-scan_work_r2}"; SRC="${3:-urls_pairs.txt}"
mkdir -p "$WD"; export FAST=1
python3 - "$WD" "$SRC" <<'PY'
import csv, glob, os, sys
WD,SRC=sys.argv[1],sys.argv[2]
done=set()
for fn in [f"{WD}/_master.csv"]+glob.glob(f"{WD}/out_*.csv"):
    if not os.path.exists(fn): continue
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
  python3 /home/user/beso/google_scan.py "'"$WD"'/shard_$i.txt" "'"$WD"'/out_$i.csv" >>"'"$WD"'/log_$i.txt" 2>&1 &
done
wait
'
python3 - "$WD" <<'PY'
import csv, glob, os, sys
from collections import Counter
WD=sys.argv[1]; done={}
for fn in [f"{WD}/_master.csv"]+sorted(glob.glob(f"{WD}/out_*.csv")):
    if not os.path.exists(fn): continue
    for r in csv.reader(open(fn)):
        if r and r[0]!="domain" and len(r)>=2: done[r[0]]=r
c=Counter(r[1] for r in done.values())
print("==== SBATCH ===="); print(f"done={len(done)}")
print(f"jwt={c.get('jwt',0)} token={c.get('token',0)} code={c.get('code',0)} unknown={c.get('google_unknown',0)} none={c.get('none',0)}")
print(f"WANT={c.get('jwt',0)+c.get('token',0)}")
PY
