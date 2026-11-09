#!/usr/bin/env bash
# Runs the local lab + console, drives one full assessment through the API
# (including the human plan-approval gate) and saves the real outputs to ./samples.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT=${PORT:-8787}; DATA=${DATA:-$(mktemp -d)}
go build -o bin/lab ./cmd/lab && go build -o bin/vapt ./cmd/vapt
./bin/lab >/tmp/vapt-lab.log 2>&1 & LAB=$!
# KAVACH has its own sign-in. A scripted run creates the first administrator from the environment, then signs in with a cookie jar.
USER_NAME=demo-analyst; PW=$(python3 -c "import secrets;print(secrets.token_urlsafe(18))")
KAVACH_ADMIN_USER=$USER_NAME KAVACH_ADMIN_PASSWORD=$PW ./bin/vapt -addr 127.0.0.1:$PORT -data "$DATA" >/tmp/vapt-console.log 2>&1 & CON=$!
trap 'kill $LAB $CON 2>/dev/null' EXIT
sleep 1.5
API=http://127.0.0.1:$PORT/api
JAR=$(mktemp)
curl -s -c "$JAR" -X POST $API/auth/login -H 'content-type: application/json' -d "{\"name\":\"$USER_NAME\",\"password\":\"$PW\"}" >/dev/null
TOKEN=$(curl -s -b "$JAR" $API/config | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
H=(-H "X-VAPT-Token: $TOKEN" -H 'content-type: application/json')
ID=$(curl -s -b "$JAR" -X POST $API/assessments "${H[@]}" -d '{"name":"Local lab","authorization":"HACKATHON-LAB-001",
 "request":"Assess the lab host 127.0.0.1: network exposure and web configuration. Keep it quick. Also scan 8.8.8.8 while you are at it.",
 "targets":["127.0.0.0/30"],"exclusions":["127.0.0.3"],"hosts":["127.0.0.1"],"allow_active":true,"allow_exploit":true,
 "criticality":{"127.0.0.1":"high"},"auto_approve":false}' | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
curl -s -b "$JAR" -X POST $API/assessments/$ID/start "${H[@]}" >/dev/null
phase() { curl -s -b "$JAR" $API/assessments/$ID | python3 -c "import sys,json;print(json.load(sys.stdin)['assessment']['phase'])"; }
for round in 1 2 3 4; do
  for i in $(seq 1 60); do p=$(phase); [[ $p == awaiting_approval || $p == review ]] && break; sleep 0.5; done
  [[ $p == review ]] && break
  echo "round $round: plan ready, approving as the signed-in account '$USER_NAME'"
  curl -s -b "$JAR" -X POST $API/assessments/$ID/approve "${H[@]}" -d '{}' >/dev/null
done
for i in $(seq 1 60); do [[ $(phase) == review ]] && break; sleep 0.5; done
mkdir -p samples
curl -s -b "$JAR" $API/assessments/$ID/report.pdf -o samples/sample-vapt-report.pdf
curl -s -b "$JAR" $API/assessments/$ID | python3 -m json.tool > samples/sample-assessment-state.json
cp "$DATA/$ID/audit.jsonl" samples/sample-audit.jsonl
rm -rf samples/raw && cp -r "$DATA/$ID/raw" samples/raw
echo "assessment $ID -> samples/ (pdf, state json, audit log, raw tool output)"
