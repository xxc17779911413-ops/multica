#!/bin/bash
set -e
WS="0e9e3f63-2b76-4af2-9181-3c25023e9279"
API="http://127.0.0.1:8080/api/workspaces/${WS}/plugins"

cd /root/multica-plugins
find time-filter helper -name '._*' -delete
find time-filter helper -name '.DS_Store' -delete

cd time-filter
rm -f ../time-filter.zip
zip -qr ../time-filter.zip multica.plugin.json ui
echo "== ZIP =="
unzip -l ../time-filter.zip | tail -6

echo "== HELPER SERVICE =="
systemctl daemon-reload
systemctl enable --now multica-time-filter-helper
sleep 2
systemctl is-active multica-time-filter-helper
echo "== HEALTH =="
curl -s http://127.0.0.1:9090/health || true
echo
echo "== QUERY TEST (today/created) =="
curl -s -X POST http://127.0.0.1:9090/query -H 'Content-Type: application/json' -d '{"input":{"range":"today","basis":"created"}}' | head -c 700
echo
echo "== QUERY TEST (this_week/schedule) =="
curl -s -X POST http://127.0.0.1:9090/query -H 'Content-Type: application/json' -d '{"input":{"range":"this_week","basis":"schedule"}}' | head -c 700
echo

echo "== INSTALL PLUGIN =="
TOKEN=$(python3 -c "import json;print(json.load(open('/root/multica-node/config/config.json'))['token'])")
UPLOAD=$(curl -s -X POST -H "Authorization: Bearer ${TOKEN}" -F bundle=@/root/multica-plugins/time-filter.zip "${API}/packages")
echo "upload: $(echo "$UPLOAD" | head -c 400)"
VID=$(echo "$UPLOAD" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('version',{}).get('id') or d.get('version_id') or '')" 2>/dev/null)
echo "version_id: ${VID}"
if [ -z "${VID}" ]; then echo "UPLOAD FAILED - stop"; exit 1; fi
PREVIEW=$(curl -s -X POST -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' -d "{\"version_id\":\"${VID}\"}" "${API}/preview")
echo "preview: $(echo "$PREVIEW" | head -c 500)"
INSTALL=$(curl -s -X POST -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' -d "{\"version_id\":\"${VID}\",\"granted_scopes\":[]}" "${API}")
echo "install: $(echo "$INSTALL" | head -c 600)"
echo
echo "== LIST INSTALLED =="
curl -s -H "Authorization: Bearer ${TOKEN}" "${API}" | head -c 900
echo
echo "DONE"
