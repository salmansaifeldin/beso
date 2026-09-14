#!/bin/bash
cd /home/user/beso
for k in $(seq 1 5); do
  bash /home/user/beso/hrun.sh 540 2>&1 | grep -E "remaining=|checked="
  rem=$(python3 - <<PY
import csv,glob,os
done=set()
for fn in glob.glob("scan_work_hidden/out_*.csv"):
    for r in csv.reader(open(fn)):
        if r and r[0]!="domain": done.add(r[0])
print(sum(1 for l in open("ALL_jwt_domains.txt") if l.strip())-len(done))
PY
)
  echo "[hidden-window $k] remaining=$rem"
  [ "$rem" -le 0 ] && break
done
echo "HIDDEN_DONE"
