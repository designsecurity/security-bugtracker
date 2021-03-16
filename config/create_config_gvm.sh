#!/bin/bash

UUID_SCAN_CONFIG=`gvm-cli --gmp-username $GVM_ADMIN_USERNAME --gmp-password $GMV_ADMIN_PASSWORD socket --socketpath /opt/gvm/var/run/gvmd.sock --xml='<create_config><copy>daba56c8-73ec-11df-a475-002264764cea</copy><name>Full with unreachable hosts</name></create_config>' | sed -E 's/.*"([a-z0-9-]*)".*/\1/'`

echo "RECOMMENDED SCAN CONFIG ID $UUID_SCAN_CONFIG"

gvm-cli --gmp-username $GVM_ADMIN_USERNAME --gmp-password $GMV_ADMIN_PASSWORD socket --socketpath /opt/gvm/var/run/gvmd.sock --xml="<modify_config config_id=\"$UUID_SCAN_CONFIG\"><preference><nvt oid=\"1.3.6.1.4.1.25623.1.0.100315\"/><name>1.3.6.1.4.1.25623.1.0.100315:5:checkbox:Mark unrechable Hosts as dead (not scanning)</name><value>bm8=</value></preference></modify_config>"

