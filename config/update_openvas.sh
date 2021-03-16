#!/bin/bash

echo "greenbone-nvt-sync"
/opt/gvm/bin/greenbone-nvt-sync
sleep 1200s
echo "greenbone-feed-sync --type GVMD_DATA"
/opt/gvm/sbin/greenbone-feed-sync --type GVMD_DATA
sleep 600s
echo "greenbone-feed-sync --type SCAP"
/opt/gvm/sbin/greenbone-feed-sync --type SCAP
sleep 600s
echo "greenbone-feed-sync --type CERT"
/opt/gvm/sbin/greenbone-feed-sync --type CERT
