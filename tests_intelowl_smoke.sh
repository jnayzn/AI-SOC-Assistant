#!/usr/bin/env bash
# IntelOwl integration smoke tests (15). Requires a running backend + a valid
# auth token. These hit the SOC backend, which proxies to your real IntelOwl.
#
#   BASE=http://localhost:8000/api/v1 TOKEN=... ANALYSIS_ID=... ./intelowl_smoke_tests.sh
set -u
BASE="${BASE:-http://localhost:8000/api/v1}"
TOKEN="${TOKEN:-}"
ANALYSIS_ID="${ANALYSIS_ID:-}"
AUTH=(-H "Authorization: Bearer ${TOKEN}")
JSON=(-H "Content-Type: application/json")
pass=0; fail=0
check() { if [ "$1" = "$2" ]; then echo "  PASS: $3 ($1)"; pass=$((pass+1)); else echo "  FAIL: $3 (got $1 want $2)"; fail=$((fail+1)); fi; }
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }

echo "1. health reachable";        check "$(code "${AUTH[@]}" "$BASE/intelowl/health")" 200 "GET /health"
echo "2. health body has configured"; curl -s "${AUTH[@]}" "$BASE/intelowl/health" | grep -q configured && echo '  PASS' || echo '  FAIL'
echo "3. scan IP";                 check "$(code -X POST "${AUTH[@]}" "${JSON[@]}" -d '{"observable":"8.8.8.8","observable_type":"ip"}' "$BASE/intelowl/scan")" 200 "POST /scan ip"
echo "4. scan domain";             check "$(code -X POST "${AUTH[@]}" "${JSON[@]}" -d '{"observable":"example.com","observable_type":"domain"}' "$BASE/intelowl/scan")" 200 "POST /scan domain"
echo "5. scan url";                check "$(code -X POST "${AUTH[@]}" "${JSON[@]}" -d '{"observable":"http://example.com","observable_type":"url"}' "$BASE/intelowl/scan")" 200 "POST /scan url"
echo "6. scan hash";               check "$(code -X POST "${AUTH[@]}" "${JSON[@]}" -d '{"observable":"44d88612fea8a8f36de82e1278abb02f","observable_type":"hash"}' "$BASE/intelowl/scan")" 200 "POST /scan hash"
echo "7. invalid type rejected";   check "$(code -X POST "${AUTH[@]}" "${JSON[@]}" -d '{"observable":"x","observable_type":"banana"}' "$BASE/intelowl/scan")" 422 "POST /scan bad type"
echo "8. empty observable rejected"; check "$(code -X POST "${AUTH[@]}" "${JSON[@]}" -d '{"observable":"","observable_type":"ip"}' "$BASE/intelowl/scan")" 422 "POST /scan empty"
echo "9. invalid tlp rejected";    check "$(code -X POST "${AUTH[@]}" "${JSON[@]}" -d '{"observable":"8.8.8.8","observable_type":"ip","tlp":"PURPLE"}' "$BASE/intelowl/scan")" 422 "POST /scan bad tlp"
echo "10. unknown job 404";        check "$(code "${AUTH[@]}" "$BASE/intelowl/jobs/does-not-exist")" 404 "GET /jobs/{bad}"
echo "11. unknown results 404";    check "$(code "${AUTH[@]}" "$BASE/intelowl/results/does-not-exist")" 404 "GET /results/{bad}"
if [ -n "$ANALYSIS_ID" ]; then
  echo "12. bulk scan analysis";   check "$(code -X POST "${AUTH[@]}" "$BASE/intelowl/scan/analysis/$ANALYSIS_ID")" 200 "POST /scan/analysis"
  echo "13. list analysis scans";  check "$(code "${AUTH[@]}" "$BASE/intelowl/analysis/$ANALYSIS_ID")" 200 "GET /analysis"
  echo "14. cache: repeat scan";   check "$(code -X POST "${AUTH[@]}" "$BASE/intelowl/scan/analysis/$ANALYSIS_ID")" 200 "POST /scan/analysis (cached)"
else
  echo "12-14. skipped (set ANALYSIS_ID to enable)"
fi
echo "15. token never exposed to client"; curl -s "${AUTH[@]}" "$BASE/intelowl/health" | grep -qi "token" && echo '  FAIL: token leaked' || echo '  PASS: no token in response'

echo ""; echo "PASS=$pass FAIL=$fail"
