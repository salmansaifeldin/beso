#!/bin/bash
d="$1"
tmp=$(mktemp -d)
echo "$d" > "$tmp/in.txt"
row=""
FAST=1 timeout 45 python3 /home/user/beso/pw_scan.py "$tmp/in.txt" "$tmp/out.csv" >/dev/null 2>&1
[ -f "$tmp/out.csv" ] && row=$(grep -v '^domain,' "$tmp/out.csv" | head -1)
[ -z "$row" ] && row="$d,none,,ERR:hang,,"
flock /home/user/beso/scan_work/tail.lock -c "printf '%s\n' \"$row\" >> /home/user/beso/scan_work/tail_out.csv"
rm -rf "$tmp"
