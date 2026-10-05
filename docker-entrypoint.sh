#!/bin/sh
set -eu

mkdir -p /run/mysqld /var/lib/mysql /var/lib/hrs_admin_router /var/log/supervisor
chown -R mysql:mysql /run/mysqld /var/lib/mysql

# Generate one secret per deployment and persist it across container restarts.
# All mod_wsgi workers inherit this same value from supervisord.
if [ -z "${SECRET_KEY:-}" ]; then
    secret_file=/var/lib/hrs_admin_router/secret_key
    if [ ! -s "$secret_file" ]; then
        umask 077
        /opt/venv/bin/python -c 'import secrets; print(secrets.token_hex(32))' > "$secret_file"
    fi
    SECRET_KEY=$(cat "$secret_file")
    export SECRET_KEY
fi

if [ ! -d /var/lib/mysql/mysql ]; then
    mariadb-install-db --user=mysql --datadir=/var/lib/mysql \
        --auth-root-authentication-method=socket --skip-name-resolve
fi

if [ ! -f /var/lib/mysql/.hrs-initialized ]; then
    /usr/sbin/mariadbd --user=mysql --datadir=/var/lib/mysql \
        --pid-file=/run/mysqld/bootstrap.pid \
        --socket=/run/mysqld/mysqld.sock \
        --skip-networking &
    mysql_pid=$!

    stop_bootstrap_db() {
        mariadb-admin --user=root --protocol=socket \
            --socket=/run/mysqld/mysqld.sock shutdown >/dev/null 2>&1 || true
        wait "$mysql_pid" 2>/dev/null || true
    }
    trap stop_bootstrap_db EXIT INT TERM

    ready=0
    for attempt in $(seq 1 60); do
        if mariadb --user=root --protocol=socket --socket=/run/mysqld/mysqld.sock \
            --execute='SELECT 1' >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 1
    done
    if [ "$ready" -ne 1 ]; then
        echo 'MariaDB did not become ready during initialization.' >&2
        exit 1
    fi

    mariadb --user=root --protocol=socket --socket=/run/mysqld/mysqld.sock <<'SQL'
CREATE DATABASE IF NOT EXISTS `database`;
CREATE USER IF NOT EXISTS 'hrs_app'@'127.0.0.1' IDENTIFIED BY 'hrs_admin_router';
GRANT ALL PRIVILEGES ON `database`.* TO 'hrs_app'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL

    mariadb-admin --user=root --protocol=socket \
        --socket=/run/mysqld/mysqld.sock shutdown
    wait "$mysql_pid"
    trap - EXIT INT TERM
    touch /var/lib/mysql/.hrs-initialized
fi

exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
