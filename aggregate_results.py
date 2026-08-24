#!/usr/bin/env python3
"""
Aggregate the raw per-domain scan CSVs into the final result files.

Reads every scan_work_g/out_*.csv (+ _master.csv), de-duplicates by domain
(keeping the last verdict), and writes:

  google_token_login_domains.txt   -> WANT: JWT + ya29 (token-returning)
  google_jwt_domains.txt           -> id_token JWT flow only
  google_token_ya29_domains.txt    -> ya29 access_token flow only
  google_code_excluded_domains.txt -> auth-code flow (excluded)
  google_sso_results.csv           -> full evidence table

Usage: python3 aggregate_results.py [work_dir] [total_expected]
"""
import csv, glob, os, sys
from collections import Counter

WD = sys.argv[1] if len(sys.argv) > 1 else "scan_work_g"
EXPECTED = int(sys.argv[2]) if len(sys.argv) > 2 else 0

done = {}
# Sources: the live shard outputs in the work dir, plus the already-aggregated
# evidence CSV (so results can be rebuilt even after the work dir is cleaned up).
sources = ([f"{WD}/_master.csv"] + sorted(glob.glob(f"{WD}/out_*.csv"))
           + [f"{WD}/tail_out.csv", "google_sso_results.csv"])
for fn in sources:
    if not os.path.exists(fn):
        continue
    for row in csv.reader(open(fn)):
        if row and row[0] != "domain" and len(row) >= 2:
            done[row[0]] = row

rows = list(done.values())
jwt = sorted(r[0] for r in rows if r[1] == "jwt")
ya29 = sorted(r[0] for r in rows if r[1] == "token")
code = sorted(r[0] for r in rows if r[1] == "code")
want = sorted(r[0] for r in rows if r[1] in ("jwt", "token"))


def dump(path, items):
    with open(path, "w") as f:
        f.write("\n".join(items) + ("\n" if items else ""))


dump("google_token_login_domains.txt", want)
dump("google_jwt_domains.txt", jwt)
dump("google_token_ya29_domains.txt", ya29)
dump("google_code_excluded_domains.txt", code)

with open("google_sso_results.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["domain", "flow", "confirmed", "evidence", "login_url", "final_url"])
    w.writerows(rows)

c = Counter(r[1] for r in rows)
print(f"scanned={len(rows)}" + (f"/{EXPECTED}" if EXPECTED else ""))
print(f"WANT(jwt+ya29)={len(want)}  jwt={len(jwt)}  ya29={len(ya29)}  "
      f"code(excluded)={len(code)}  none={c.get('none', 0)}")
