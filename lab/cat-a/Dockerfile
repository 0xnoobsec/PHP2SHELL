ARG PHP_VERSION=8.1
FROM php:${PHP_VERSION}-apache

RUN a2enmod rewrite

COPY php.ini /usr/local/etc/php/php.ini
COPY index.php /var/www/html/index.php
COPY info.php /var/www/html/info.php
COPY slow.php /var/www/html/slow.php

RUN mkdir -p /var/lib/php/sessions && \
    chown www-data:www-data /var/lib/php/sessions && \
    chmod 1733 /var/lib/php/sessions

EXPOSE 80
