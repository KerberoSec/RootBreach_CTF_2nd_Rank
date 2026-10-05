FROM haproxy:2.0.5

# Fix broken Debian Buster repos (moved to archive)
RUN sed -i 's|deb.debian.org/debian|archive.debian.org/debian|g' /etc/apt/sources.list && \
    sed -i 's|security.debian.org/debian-security|archive.debian.org/debian-security|g' /etc/apt/sources.list && \
    sed -i '/buster-updates/d' /etc/apt/sources.list && \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid

RUN apt-get update && apt-get install -y gettext-base --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

COPY haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
