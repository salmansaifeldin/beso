#!/bin/bash
# Isolated per-domain deep scan for stragglers: one process per domain, hard timeout.
cd /home/user/beso
WD="${1:-scan_work_deep}"; SRC="${2:-deep_pairs.txt}"; DUR="${3:-1700}"
OUT="$WD/iso_out.csv"
[ -f "$OUT" ] || echo "domain,g_cat,g_ev,ms_cat,ms_ev,login_url" > "$OUT"
# remaining = in SRC but not in any out_*.csv or iso_out.csv
python3 - "$WD" "$SRC" > /tmp/iso_rem.txt <<'PY'
import csv, glob, sys
WD,SRC=sys.argv[1],sys.argv[2]
done=set()
for fn in glob.glob(f"{WD}/out_*.csv")+[f"{WD}/iso_out.csv"]:
    try:
        for r in csv.reader(open(fn)):
            if r and r[0]!="domain": done.add(r[0])
    except: pass
for l in open(SRC):
    d=l.strip()
    if d and d not in done: print(d)
PY
echo "iso remaining=$(wc -l < /tmp/iso_rem.txt)"
END=$(( $(date +%s) + DUR ))
run_one(){
  d="$1"
  printf "%s\n" "$d" > "/tmp/iso_$2.txt"
  timeout 40 python3 /home/user/beso/deep_scan.py "/tmp/iso_$2.txt" "/tmp/iso_${2}_out.csv" >/dev/null 2>&1
  row=$(grep -v "^domain," "/tmp/iso_${2}_out.csv" 2>/dev/null | head -1)
  [ -z "$row" ] && row="$d,err,timeout,none,,"
  echo "$row" >> "$OUT"
  rm -f "/tmp/iso_$2.txt" "/tmp/iso_${2}_out.csv"
  echo "$row"
}
export -f run_one
i=0
while read -r d; do
  [ $(date +%s) -ge $END ] && { echo "time budget hit"; break; }
  # 6 in parallel
  run_one "$d" $((i%6)) &
  i=$((i+1))
  if [ $((i%6)) -eq 0 ]; then wait; fi
done < /tmp/iso_rem.txt
wait
echo "done iso round"
