#!/bin/bash
cd /home/user/beso
N="${1:-16}"; SRC=big_domains.txt; WD=scan_work_big
for k in $(seq 1 "$N"); do
  bash /home/user/beso/giso_big.sh 540 2>&1 | grep -E "done=|remaining"
  rem=$(python3 - <<PY
import csv,glob,os
done=set()
for fn in ["$WD/_master.csv"]+glob.glob("$WD/out_*.csv")+["$WD/tail_out.csv"]:
    if os.path.exists(fn):
        for r in csv.reader(open(fn)):
            if r and r[0]!="domain": done.add(r[0])
print(sum(1 for l in open("$SRC") if l.strip())-len(done))
PY
)
  echo "[iso-window $k] remaining=$rem"
  [ "$rem" -le 0 ] && break
done
echo "BIGRUN_ISO_DONE"
