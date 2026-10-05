#!/bin/sh
set -eu

for attempt in $(seq 1 60); do
    if mariadb --user=hrs_app --password=hrs_admin_router \
        --host=127.0.0.1 --database=database --execute='SELECT 1' \
        >/dev/null 2>&1; then
        exec /usr/sbin/apache2ctl -D FOREGROUND
    fi
    sleep 1
done

echo 'MariaDB was not ready; Apache was not started.' >&2
exit 1
