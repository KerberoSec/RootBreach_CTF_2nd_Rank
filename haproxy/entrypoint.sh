#!/bin/sh
set -eu

: "${SERVER_HOSTNAME:=mitmproxy}"
: "${SERVER_PORT:=8002}"
export SERVER_HOSTNAME SERVER_PORT

envsubst < /usr/local/etc/haproxy/haproxy.cfg.template \
    > /usr/local/etc/haproxy/haproxy.cfg
exec haproxy -db -f /usr/local/etc/haproxy/haproxy.cfg
