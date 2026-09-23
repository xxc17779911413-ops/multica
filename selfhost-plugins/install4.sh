#!/bin/bash
WS="0e9e3f63-2b76-4af2-9181-3c25023e9279"
API="http://127.0.0.1:8080/api/workspaces/${WS}/plugins"
VID="0d3633e7-d4b4-4a77-b6de-747b3afaf09e"
TOKEN=$(python3 -c "import json;print(json.load(open('/root/multica-node/config/config.json'))['token'])")

echo "== PREVIEW =="
curl -s -X POST -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
  -d "{\"version_id\":\"${VID}\"}" "${API}/preview" | head -c 800
echo
echo "== INSTALL =="
INSTALL=$(curl -s -X POST -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
  -d "{\"version_id\":\"${VID}\",\"granted_scopes\":[\"issues:read\",\"net:host.docker.internal\"]}" "${API}")
echo "$INSTALL" | head -c 900
echo
IID=$(echo "$INSTALL" | python3 -c "import json,sys;d=json.load(sys.stdin);print((d.get('installation') or d).get('id',''))" 2>/dev/null)
echo "iid=${IID}"
if [ -n "${IID}" ]; then
  echo "== ENABLE =="
  curl -s -X POST -H "Authorization: Bearer ${TOKEN}" "${API}/${IID}/enable" | head -c 400
  echo
fi
echo "== LIST =="
curl -s -H "Authorization: Bearer ${TOKEN}" "${API}" | head -c 1500
echo
echo DONE
