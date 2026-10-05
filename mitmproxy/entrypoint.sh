#!/bin/sh
set -eu

: "${SERVER_HOSTNAME:=127.0.0.1}"
: "${SERVER_PORT:=80}"
exec mitmdump --mode "reverse:http://${SERVER_HOSTNAME}:${SERVER_PORT}" \
    -p 8002 --set block_global=false --set keep_host_header=true --no-http2
