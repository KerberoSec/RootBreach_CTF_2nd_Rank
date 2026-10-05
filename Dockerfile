FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Keep Apache/mod_wsgi on Debian's Python and install application packages in
# a venv built from that same interpreter (required by PEP 668 on Bookworm).
RUN apt-get update && apt-get install -y --no-install-recommends \
    mariadb-server \
    apache2 \
    libapache2-mod-wsgi-py3 \
    python3 \
    python3-venv \
    haproxy \
    curl \
    supervisor \
    gettext-base \
    netcat-traditional \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY app/website/requirements.txt /tmp/website-requirements.txt
COPY app/internal/requirements.txt /tmp/internal-requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /tmp/website-requirements.txt \
    && pip install --no-cache-dir -r /tmp/internal-requirements.txt \
    && pip install --no-cache-dir mitmproxy==11.0.2

# External Flask website
WORKDIR /var/www/hrs_admin_router
COPY app/website/hrs_admin_router.wsgi .
COPY app/website/run.py .
COPY app/website/app ./app

# Internal router API
WORKDIR /var/www/internal_router
COPY app/internal/internal_router.wsgi .
COPY app/internal/run.py .
COPY app/internal/app ./app

ARG FLAG=flag{development_placeholder}
RUN printf '%s' "$FLAG" > /flag

# Apache virtual hosts and supporting service configuration
COPY app/hrs_admin_router-httpd.conf /etc/apache2/sites-available/hrs_admin_router-httpd.conf
RUN a2dissite 000-default.conf \
    && a2ensite hrs_admin_router-httpd.conf \
    && a2enmod headers

COPY haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.template
COPY supervisord.conf /etc/supervisor/supervisord.conf
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY docker/start-apache.sh /usr/local/bin/start-apache.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh /usr/local/bin/start-apache.sh \
    && mkdir -p /run/mysqld /var/lib/mysql /var/lib/hrs_admin_router \
    && chown -R mysql:mysql /run/mysqld /var/lib/mysql

EXPOSE 80 8001 8002

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
