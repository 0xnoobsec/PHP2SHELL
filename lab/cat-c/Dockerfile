FROM php:8.1-apache

# Category C baseline: an unserialize() endpoint for the back-reference probe.
# Detection only: on this build the probe decodes without corruption. This is
# not CVE-2026-109618; that study runs against lab/cat-c-vuln.

RUN a2enmod rewrite

COPY php.ini /usr/local/etc/php/php.ini
COPY decode.php /var/www/html/decode.php
COPY index.php /var/www/html/index.php
COPY info.php /var/www/html/info.php

# Session directory
RUN mkdir -p /var/lib/php/sessions && \
    chown www-data:www-data /var/lib/php/sessions && \
    chmod 1733 /var/lib/php/sessions

EXPOSE 80
