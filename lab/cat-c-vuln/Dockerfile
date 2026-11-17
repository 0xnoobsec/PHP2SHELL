# The CVE-2026-109618 study environment: mod_php, prefork, one worker,
# memory_limit far below what a nested multipart body expands to.
#
# 8.4.26 is the last 8.4 release without the fix. For a patched comparison in
# the same configuration, build this directory with another version:
#   docker build --build-arg PHP_VERSION=8.4.27 -t p2s-c8427 .
ARG PHP_VERSION=8.4.26
FROM php:${PHP_VERSION}-apache
RUN a2enmod rewrite
COPY php.ini /usr/local/etc/php/php.ini
COPY mpm.conf /etc/apache2/mods-available/mpm_prefork.conf
COPY decode.php /var/www/html/decode.php
COPY index.php /var/www/html/index.php
COPY probe.php /var/www/html/probe.php
RUN mkdir -p /var/lib/php/sessions && chown www-data:www-data /var/lib/php/sessions && chmod 1733 /var/lib/php/sessions
EXPOSE 80
