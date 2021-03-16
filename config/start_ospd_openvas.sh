#!/bin/bash

/usr/sbin/apache2ctl

/usr/sbin/redis-server /etc/redis/redis-openvas.conf --daemonize yes

# https://community.greenbone.net/t/after-update-to-the-last-components-of-the-gvm-11-series-vts-are-missing/5363/5
# not needed (done by ospd-openvas)
# /opt/gvm/sbin/openvas --update-vt-info

/usr/bin/initdb -D /opt/gvm/postgres/

/usr/bin/pg_ctl -D /opt/gvm/postgres/ -l logfile start

createuser -DRS gvm || true
createdb -O gvm gvmd || true
psql gvmd --command "create role dba with superuser noinherit; grant dba to gvm;create extension \"uuid-ossp\";create extension \"pgcrypto\";" || true

UUID_DEFAULT_SCANNER=`/opt/gvm/sbin/gvmd --get-scanners | sed -E 's/([a-z0-9-]*) .*/\1/' | head -n 1`

echo "DEFAULT SCANNER ID $UUID_DEFAULT_SCANNER"

rm /opt/gvm/var/run/ospd-openvas.pid

/opt/gvm/sbin/gvmd --modify-scanner=$UUID_DEFAULT_SCANNER --scanner-host=/opt/gvm/var/run/ospd.sock

/opt/gvm/sbin/gvmd --create-user=$GVM_ADMIN_USERNAME --password=$GVM_ADMIN_PASSWORD

UUID_ADMIN_USER=`/opt/gvm/sbin/gvmd --get-users --verbose | sed -E 's/.* ([a-z0-9-]*)/\1/'`

# configure "Feed Import Owner" right:
/opt/gvm/sbin/gvmd --modify-setting 78eceaec-3385-11ea-b237-28d24461215b --value $UUID_ADMIN_USER

/opt/gvm/sbin/gvmd

/opt/gvm/sbin/gsad

sleep 5s

python3 /opt/gvm/bin/ospd-openvas --pid-file /opt/gvm/var/run/ospd-openvas.pid --log-file /opt/gvm/var/log/gvm/ospd-openvas.log --log-level DEBUG --lock-file-dir /opt/gvm/var/run -u /opt/gvm/var/run/ospd.sock -f
