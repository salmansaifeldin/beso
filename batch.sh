#!/bin/bash
# One foreground batch: run 8 resumable workers for ~9.5 min, then report.
cd /home/user/beso
DUR="${1:-575}"
export FAST=1
timeout "$DUR" bash -c '
export FAST=1
for i in $(seq 0 7); do
  python3 /home/user/beso/pw_scan.py "scan_work/shard8_$i.txt" "scan_work/out8_$i.csv" >>"scan_work/log8_$i.txt" 2>&1 &
done
wait
'
new=$(cat scan_work/out8_*.csv 2>/dev/null | grep -vc '^domain,')
master=$(grep -vc '^domain,' scan_work/_master.csv 2>/dev/null)
total=$((new+master))
ms=$(cat scan_work/_master.csv scan_work/out8_*.csv 2>/dev/null | awk -F, '$2=="microsoft"' | wc -l)
sso=$(cat scan_work/_master.csv scan_work/out8_*.csv 2>/dev/null | awk -F, '$2=="generic_sso"' | wc -l)
echo "==== BATCH DONE ===="
echo "TOTAL=$total/8195  remaining=$((8195-total))  (new_this_session=$new)"
echo "microsoft=$ms  generic_sso=$sso  total_hits=$((ms+sso))"
