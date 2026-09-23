#!/bin/bash
set -e
WS="0e9e3f63-2b76-4af2-9181-3c25023e9279"
API="http://127.0.0.1:8080/api/workspaces/${WS}/plugins"

cd /root/multica-plugins/time-filter
rm -f ../time-filter.zip
zip -qr ../time-filter.zip multica.plugin.json ui

TOKEN=$(python3 -c "import json;print(json.load(open('/root/multica-node/config/config.json'))['token'])")
UPLOAD=$(curl -s -X POST -H "Authorization: Bearer ${TOKEN}" -F bundle=@/root/multica-plugins/time-filter.zip "${API}/packages")
echo "upload: $(echo "$UPLOAD" | head -c 500)"
VID=$(echo "$UPLOAD" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('version',{}).get('id') or d.get('version_id') or '')" 2>/dev/null)
[ -z "${VID}" ] && { echo NO-VID; exit 1; }

PREVIEW=$(curl -s -X POST -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' -d "{\"version_id\":\"${VID}\"}" "${API}/preview")
echo "preview: $(echo "$PREVIEW" | head -c 700)"

INSTALL=$(curl -s -X POST -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' -d "{\"version_id\":\"${VID}\",\"granted_scopes\":[\"issues:read\"]}" "${API}")
echo "install: $(echo "$INSTALL" | head -c 800)"

IID=$(echo "$INSTALL" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('installation',{}).get('id') or d.get('id') or '')" 2>/dev/null)
echo "installation_id: ${IID}"
if [ -n "${IID}" ]; then
  curl -s -X POST -H "Authorization: Bearer ${TOKEN}" "${API}/${IID}/enable" > /dev/null
  echo "enabled"
fi

echo "== LIST =="
curl -s -H "Authorization: Bearer ${TOKEN}" "${API}" | python3 -m json.tool 2>/dev/null | head -50 || curl -s -H "Authorization: Bearer ${TOKEN}" "${API}" | head -c 900
echo
echo INSTALL-DONE
