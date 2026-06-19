#!/bin/bash
# Resilient batch: fold previous results into master, RESHUFFLE remaining into
# 8 fresh shards (so a hung domain can't permanently block one shard), run 8
# workers for ~9 min, then report. Safe against data loss (out8 folded into
# master before being cleared).
cd /home/user/beso
DUR="${1:-560}"
export FAST=1

python3 - <<'PY'
import csv, glob, os, random
done={}
for fn in ["scan_work/_master.csv"]+sorted(glob.glob("scan_work/out8_*.csv")):
    if not os.path.exists(fn): continue
    for row in csv.reader(open(fn)):
        if row and row[0]!="domain" and len(row)>=2: done[row[0]]=row
# persist consolidated master FIRST (so out8 data is safe), then clear shards
csv.writer(open("scan_work/_master.csv","w",newline="")).writerows(done.values())
alld=[l.strip() for l in open("domains_all.txt") if l.strip()]
rem=[d for d in alld if d not in done]
random.shuffle(rem)
N=8
for i in range(N):
    open(f"scan_work/shard8_{i}.txt","w").write("\n".join(rem[i::N])+"\n")
    open(f"scan_work/out8_{i}.csv","w").close()   # fresh empty for this batch
print(f"start master={len(done)} remaining={len(rem)}")
PY

timeout "$DUR" bash -c 'export FAST=1; for i in $(seq 0 7); do python3 /home/user/beso/pw_scan.py "scan_work/shard8_$i.txt" "scan_work/out8_$i.csv" >>"scan_work/log8_$i.txt" 2>&1 & done; wait'

python3 - <<'PY'
import csv, glob, os
done={}
for fn in ["scan_work/_master.csv"]+sorted(glob.glob("scan_work/out8_*.csv")):
    if not os.path.exists(fn): continue
    for row in csv.reader(open(fn)):
        if row and row[0]!="domain" and len(row)>=2: done[row[0]]=row
ms=sum(1 for r in done.values() if r[1]=="microsoft")
sso=sum(1 for r in done.values() if r[1]=="generic_sso")
print("==== BATCH DONE ====")
print(f"TOTAL={len(done)}/8195  remaining={8195-len(done)}  microsoft={ms}  generic_sso={sso}")
PY
