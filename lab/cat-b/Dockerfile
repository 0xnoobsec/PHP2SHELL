ARG PHP_VERSION=8.1
FROM php:${PHP_VERSION}-apache

RUN a2enmod rewrite

# Install composer for Monolog (POP gadget chain target)
COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer

# Create two directories with different session serialize handlers
RUN mkdir -p /var/www/html/seed /var/www/html/fire
RUN mkdir -p /var/lib/php/sessions && \
    chown www-data:www-data /var/lib/php/sessions && \
    chmod 1733 /var/lib/php/sessions

# PHP configs: one per directory
COPY php-seed.ini /usr/local/etc/php/conf.d/seed.ini
COPY php-fire.ini /usr/local/etc/php/php.ini

# Application files
COPY seed.php /var/www/html/seed/index.php
COPY fire.php /var/www/html/fire/index.php
COPY gadget.php /var/www/html/gadget.php
COPY info.php /var/www/html/info.php
COPY index.php /var/www/html/index.php

# Install Monolog for POP gadget chain testing
COPY composer.json /var/www/html/composer.json
RUN cd /var/www/html && composer install --no-dev --no-interaction 2>/dev/null || true

# Apache config to apply different php.ini per directory
COPY apache-dirs.conf /etc/apache2/conf-enabled/dirs.conf

EXPOSE 80
