FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 \
    libapache2-mod-wsgi-py3 \
    python3 \
    python3-venv \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY ./website/requirements.txt /tmp/website-requirements.txt
COPY ./internal/requirements.txt /tmp/internal-requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /tmp/website-requirements.txt \
    && pip install --no-cache-dir -r /tmp/internal-requirements.txt

COPY ./hrs_admin_router-httpd.conf /etc/apache2/sites-available/hrs_admin_router-httpd.conf

WORKDIR /var/www/hrs_admin_router
COPY ./website/hrs_admin_router.wsgi .
COPY ./website/run.py .
COPY ./website/app ./app

WORKDIR /var/www/internal_router
COPY ./internal/internal_router.wsgi .
COPY ./internal/run.py .
COPY ./internal/app ./app

ARG FLAG=flag{development_placeholder}
RUN printf '%s' "$FLAG" > /flag \
    && a2dissite 000-default.conf \
    && a2ensite hrs_admin_router-httpd.conf \
    && a2enmod headers

EXPOSE 80
CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]
