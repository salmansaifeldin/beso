#!/bin/bash
cd /home/user/beso
DUR="${1:-1700}"; WD="${2:-scan_work_deep}"; SRC="${3:-deep_pairs.txt}"
mkdir -p "$WD"
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
WD="'"$WD"'"
for i in $(seq 0 7); do
  python3 /home/user/beso/deep_scan.py "$WD/shard_$i.txt" "$WD/out_$i.csv" >>"$WD/log_$i.txt" 2>&1 &
done
wait
'
echo "==== DBATCH ===="
cat "$WD"/out_*.csv 2>/dev/null | grep -v "^domain," | awk -F, '{print "G:"$2}' | sort | uniq -c
cat "$WD"/out_*.csv 2>/dev/null | grep -v "^domain," | awk -F, '{print "MS:"$4}' | sort | uniq -c
