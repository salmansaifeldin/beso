#!/bin/bash
cd /home/user/beso
DUR="${1:-540}"; WD=scan_work_big; SRC=big_domains.txt
python3 - "$WD" "$SRC" <<'PY'
import csv, glob, os, sys
WD, SRC = sys.argv[1], sys.argv[2]
done=set()
for fn in [f"{WD}/_master.csv"]+sorted(glob.glob(f"{WD}/out_*.csv"))+[f"{WD}/tail_out.csv"]:
    if not os.path.exists(fn): continue
    for r in csv.reader(open(fn)):
        if r and r[0]!="domain": done.add(r[0])
rem=[d for d in (l.strip() for l in open(SRC)) if d and d not in done]
open(f"{WD}/iso_remaining.txt","w").write("\n".join(rem)+"\n")
print(f"iso remaining: {len(rem)}")
PY
[ -f "$WD/tail_out.csv" ] || touch "$WD/tail_out.csv"
timeout "$DUR" bash -c 'cat scan_work_big/iso_remaining.txt | xargs -P 8 -I{} bash gone_big.sh {}'
python3 - "$WD" "$SRC" <<'PY'
import csv, glob, os, sys
from collections import Counter
WD, SRC = sys.argv[1], sys.argv[2]
done={}
for fn in [f"{WD}/_master.csv"]+sorted(glob.glob(f"{WD}/out_*.csv"))+[f"{WD}/tail_out.csv"]:
    if not os.path.exists(fn): continue
    for r in csv.reader(open(fn)):
        if r and r[0]!="domain" and len(r)>=2: done[r[0]]=r
total=len([l for l in open(SRC) if l.strip()]); n=len(done)
c=Counter(r[1] for r in done.values())
print(f"done={n}/{total} remaining={total-n} WANT={c.get('jwt',0)+c.get('token',0)}")
PY
