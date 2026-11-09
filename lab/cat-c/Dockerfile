FROM php:8.1-apache

# Category C lab: UAF via VAR_ENTRIES_MAX overflow in unserialize()
# CVE-2026-109618: back-reference overflow past 1018 entries triggers use-after-free

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
