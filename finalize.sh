#!/bin/bash
# Wait for the scan to finish, then verify + report + commit/push. Self-running.
cd /home/user/beso
until grep -q "\[done\]" scan.log 2>/dev/null && ! pgrep -f repo-dep-scan >/dev/null; do
  sleep 20
done
echo "scan done -> verifying"
node verify.js repo-results.jsonl verified.jsonl verified-report.md 2>&1 | tail -5
node report.js repo-results.jsonl report.md 2>&1 | tail -3
cp repo-results.jsonl repo-results.snapshot.jsonl
git add -f repo-results.jsonl repo-results.snapshot.jsonl verified.jsonl verified-report.md report.md
git add -A
git commit -q -m "Finalize: complete scan results + verified findings + reports

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018dWyM5WKXbrCV7VhmNgXDW"
for i in 1 2 3 4; do git push origin claude/adoring-carson-vqd6q4 && break || sleep $((2**i)); done
echo "FINALIZED"
