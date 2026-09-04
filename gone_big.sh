#!/bin/bash
d="$1"; tmp=$(mktemp -d); row=""
if curl -sS -m 6 -o /dev/null -A "Mozilla/5.0" "https://$d/" 2>/dev/null \
   || curl -sS -m 6 -o /dev/null -A "Mozilla/5.0" "https://www.$d/" 2>/dev/null; then
  echo "$d" > "$tmp/in.txt"
  FAST=1 timeout 30 python3 /home/user/beso/google_scan.py "$tmp/in.txt" "$tmp/out.csv" >/dev/null 2>&1
  [ -f "$tmp/out.csv" ] && row=$(grep -v '^domain,' "$tmp/out.csv" | head -1)
  [ -z "$row" ] && row="$d,none,,ERR:hang,,"
else
  row="$d,none,,ERR:unreachable,,"
fi
flock /home/user/beso/scan_work_big/tail.lock -c "printf '%s\n' \"$row\" >> /home/user/beso/scan_work_big/tail_out.csv"
rm -rf "$tmp"
