#!/bin/bash
# Loop the main scanner over the big list for N windows (resumable).
cd /home/user/beso
N="${1:-8}"; WD=scan_work_big; SRC=big_domains.txt
for k in $(seq 1 "$N"); do
  bash /home/user/beso/sbatch.sh 540 "$WD" "$SRC" 2>&1 | grep -E "done=|remaining="
  # stop early if nothing remaining
  rem=$(python3 - <<PY
import csv,glob,os
done=set()
for fn in ["$WD/_master.csv"]+glob.glob("$WD/out_*.csv"):
    if os.path.exists(fn):
        for r in csv.reader(open(fn)):
            if r and r[0]!="domain": done.add(r[0])
tot=sum(1 for l in open("$SRC") if l.strip())
print(tot-len(done))
PY
)
  echo "[window $k] remaining=$rem"
  [ "$rem" -le 0 ] && break
done
echo "BIGRUN_LOOP_DONE"
