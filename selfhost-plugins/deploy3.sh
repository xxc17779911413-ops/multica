#!/bin/bash
set -e
cp /root/multica-plugins/helper/multica-time-filter-helper.service /etc/systemd/system/
systemctl daemon-reload
systemctl restart multica-time-filter-helper
sleep 2
echo "== TLS HEALTH =="
curl -sk https://127.0.0.1:9090/health
echo
echo "== BACKEND RECREATE =="
cd /root/multica
docker compose -f docker-compose.selfhost.yml -f docker-compose.selfhost.lan.yml -f docker-compose.plugin.yml up -d backend 2>&1 | tail -2
sleep 8
echo "== REINSTALL =="
bash /root/multica-plugins/install2.sh
