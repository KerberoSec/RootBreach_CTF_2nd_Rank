FROM mitmproxy/mitmproxy:6.0.2

RUN apt-get update && apt-get install -y gettext-base --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create entrypoint script to substitute environment variables
RUN echo '#!/bin/sh\nEXEC="mitmdump --mode reverse:http://'"'"'${SERVER_HOSTNAME}:${SERVER_PORT}'"'"' -p 8002 --set block_global=false --no-http2"\neval "$EXEC"' > /entrypoint.sh && \
    chmod +x /entrypoint.sh

ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]