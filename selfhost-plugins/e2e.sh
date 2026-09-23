#!/bin/bash
WS="0e9e3f63-2b76-4af2-9181-3c25023e9279"
API="http://127.0.0.1:8080/api"
VID_IID="74ae54d5-b6e6-4437-a9cc-3fc9a66ec1b6"
TOKEN=$(python3 -c "import json;print(json.load(open('/root/multica-node/config/config.json'))['token'])")
USERID="3c55068f-2096-4d51-9f88-f05844cfd131"

echo "== HOOK E2E: today/created =="
curl -s -m 60 -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-User-ID: ${UID}" \
  -H "X-Multica-Plugin-Installation: ${VID_IID}" \
  -H 'Content-Type: application/json' \
  -d '{"trigger":"ui","input":{"range":"today","basis":"created"}}' \
  "${API}/plugin-bridge/v1/hooks/query" | head -c 900
echo
echo "== HOOK E2E: last_week/schedule =="
curl -s -m 60 -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-User-ID: ${UID}" \
  -H "X-Multica-Plugin-Installation: ${VID_IID}" \
  -H 'Content-Type: application/json' \
  -d '{"trigger":"ui","input":{"range":"last_week","basis":"schedule"}}' \
  "${API}/plugin-bridge/v1/hooks/query" | head -c 900
echo
echo DONE
