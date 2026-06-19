#!/bin/bash
# Parallel Microsoft-SSO crawl across all domains using N browser workers.
set -u
INPUT="${1:-domains_all.txt}"
SHARDS="${2:-12}"
WORKDIR="/home/user/beso/scan_work"
mkdir -p "$WORKDIR"

# Split input into SHARDS round-robin (keeps load even across the alphabet)
python3 - "$INPUT" "$SHARDS" "$WORKDIR" <<'PY'
import sys
inp, n, wd = sys.argv[1], int(sys.argv[2]), sys.argv[3]
doms=[l.strip() for l in open(inp) if l.strip()]
files=[open(f"{wd}/shard_{i}.txt","w") for i in range(n)]
for idx,d in enumerate(doms):
    files[idx % n].write(d+"\n")
for f in files: f.close()
print(f"split {len(doms)} domains into {n} shards")
PY

pids=()
for i in $(seq 0 $((SHARDS-1))); do
  python3 /home/user/beso/pw_scan.py "$WORKDIR/shard_${i}.txt" "$WORKDIR/out_${i}.csv" \
      > "$WORKDIR/log_${i}.txt" 2>&1 &
  pids+=($!)
done
echo "launched ${#pids[@]} workers: ${pids[*]}"
for p in "${pids[@]}"; do wait "$p"; done
echo "ALL_WORKERS_DONE"

# merge
python3 - "$WORKDIR" "$SHARDS" <<'PY'
import sys, csv, glob, os
wd, n = sys.argv[1], int(sys.argv[2])
rows=[]
for i in range(n):
    fn=f"{wd}/out_{i}.csv"
    if not os.path.exists(fn): continue
    with open(fn) as f:
        r=list(csv.reader(f))
    for row in r:
        if row and row[0]!="domain":
            rows.append(row)
with open("/home/user/beso/ms_sso_results.csv","w",newline="") as f:
    w=csv.writer(f)
    w.writerow(["domain","category","confirmed","evidence","login_url","final_url"])
    w.writerows(rows)
ms=[r[0] for r in rows if r[1]=="microsoft"]
sso=[r[0] for r in rows if r[1]=="generic_sso"]
open("/home/user/beso/microsoft_login_domains.txt","w").write("\n".join(ms)+("\n" if ms else ""))
open("/home/user/beso/microsoft_plus_sso_domains.txt","w").write("\n".join(ms+sso)+("\n" if (ms or sso) else ""))
print(f"MERGED total={len(rows)} microsoft={len(ms)} generic_sso={len(sso)}")
PY
echo "MERGE_DONE"
