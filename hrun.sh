#!/bin/bash
cd /home/user/beso
DUR="${1:-540}"; WD=scan_work_hidden; SRC=ALL_jwt_domains.txt
mkdir -p "$WD"
python3 - "$WD" "$SRC" <<'PY'
import csv, glob, os, sys
WD,SRC=sys.argv[1],sys.argv[2]
done=set()
for fn in glob.glob(f"{WD}/out_*.csv"):
    for r in csv.reader(open(fn)):
        if r and r[0]!="domain": done.add(r[0])
rem=[l.strip() for l in open(SRC) if l.strip() and l.strip() not in done]
for f in glob.glob(f"{WD}/shard_*.txt"): os.remove(f)
N=8
fs=[open(f"{WD}/shard_{i}.txt","w") for i in range(N)]
for i,d in enumerate(rem): fs[i%N].write(d+"\n")
for f in fs: f.close()
print(f"remaining={len(rem)}")
PY
timeout "$DUR" bash -c '
for i in $(seq 0 7); do
  python3 /home/user/beso/hidden_check.py "scan_work_hidden/shard_$i.txt" "scan_work_hidden/out_$i.csv" >>"scan_work_hidden/log_$i.txt" 2>&1 &
done
wait
'
python3 - <<'PY'
import csv, glob, os
from collections import Counter
done={}
for fn in glob.glob("scan_work_hidden/out_*.csv"):
    for r in csv.reader(open(fn)):
        if r and r[0]!="domain" and len(r)>=2: done[r[0]]=r
c=Counter(r[1] for r in done.values())
print(f"checked={len(done)}  hidden={c.get('hidden',0)} visible={c.get('visible',0)} none={c.get('none',0)} unreachable={c.get('unreachable',0)}")
PY
