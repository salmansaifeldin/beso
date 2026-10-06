#!/bin/bash
# grun.sh <workdir> : scans urls.txt in workdir, 6 parallel, resumable
WD="$1"
OUT="$WD/out.csv"
touch "$OUT"
export PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers
run_one(){
  local url="$1" wd="$2"
  local dom=$(python3 -c "import sys;from urllib.parse import urlparse;h=urlparse(sys.argv[1]).netloc.lower().split(':')[0];p=h.split('.');print(h if len(p)<=2 else '.'.join(p[-2:]))" "$url")
  grep -q "^${dom}	" "$wd/out.csv" 2>/dev/null && return
  timeout 75 python3 /home/user/beso/gscan_url.py "$url" "$wd/out.csv" >/dev/null 2>&1 \
    || echo -e "${dom}\terror\ttimeout\t\t${url}" >> "$wd/out.csv"
}
export -f run_one
cat "$WD/urls.txt" | xargs -P 6 -I {} bash -c 'run_one "$@"' _ {} "$WD"
echo "DONE $(wc -l < $OUT) rows"
