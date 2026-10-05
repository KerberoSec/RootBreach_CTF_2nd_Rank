FROM mitmproxy/mitmproxy:11.0.2

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

ENV SERVER_HOSTNAME=127.0.0.1 \
    SERVER_PORT=80

EXPOSE 8002
ENTRYPOINT ["/entrypoint.sh"]
