FROM debian:bullseye-slim

# Install all dependencies
RUN apt-get update && apt-get install -y \
    mariadb-server \
    apache2 \
    libapache2-mod-wsgi-py3 \
    python3 \
    python3-pip \
    haproxy \
    curl \
    supervisor \
    gettext-base \
    netcat-traditional \
    && pip3 install mitmproxy \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set up Flask app requirements
WORKDIR /var/www/hrs_admin_router
COPY ./app/website/requirements.txt app/requirements.txt
RUN pip install -r app/requirements.txt

COPY ./app/website/hrs_admin_router.wsgi .
COPY ./app/website/run.py .
COPY ./app/website/app ./app

# Set up internal router
WORKDIR /var/www/internal_router
COPY ./app/internal/requirements.txt app/requirements.txt
RUN pip install -r app/requirements.txt

COPY ./app/internal/internal_router.wsgi .
COPY ./app/internal/run.py .
COPY ./app/internal/app ./app

# Set flag
ARG FLAG
RUN echo -n "$FLAG" > /flag

# Setup Apache
COPY ./app/hrs_admin_router-httpd.conf /etc/apache2/sites-available/hrs_admin_router-httpd.conf
RUN a2dissite 000-default.conf && \
    a2ensite hrs_admin_router-httpd.conf && \
    a2enmod headers

# Setup MariaDB
RUN mkdir -p /run/mysqld /var/lib/mysql && \
    chown -R mysql:mysql /run/mysqld /var/lib/mysql && \
    mysql_install_db --user=mysql --datadir=/var/lib/mysql --skip-name-resolve --no-defaults 2>/dev/null || true

# Setup HAProxy template
COPY ./haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.template

# Setup mitmproxy entrypoint script
RUN mkdir -p /mitmproxy

# Create supervisor config
RUN mkdir -p /etc/supervisor/conf.d
COPY supervisord.conf /etc/supervisor/supervisord.conf

# Create startup script that initializes the database
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Start MariaDB temporarily to set up database\n\
/usr/sbin/mysqld --user=mysql --datadir=/var/lib/mysql &\n\
MYSQL_PID=$!\n\
\n\
# Wait for MariaDB to be ready\n\
for i in {1..30}; do\n\
    if mysqladmin ping -h localhost 2>/dev/null; then\n\
        break\n\
    fi\n\
    sleep 1\n\
done\n\
\n\
# Initialize database and user\n\
mysql -u root <<EOF\n\
ALTER USER "root"@"localhost" IDENTIFIED BY "hrs_admin_router";\n\
CREATE DATABASE IF NOT EXISTS \`database\`;\n\
FLUSH PRIVILEGES;\n\
EOF\n\
\n\
# Stop temporary MariaDB\n\
kill $MYSQL_PID 2>/dev/null || true\n\
wait $MYSQL_PID 2>/dev/null || true\n\
\n\
# Start supervisord\n\
exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf\n\
' > /entrypoint.sh && chmod +x /entrypoint.sh

EXPOSE 80 8001 8002

ENTRYPOINT ["/entrypoint.sh"]
