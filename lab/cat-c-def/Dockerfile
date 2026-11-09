FROM php:8.4.26-apache-bookworm
RUN a2enmod rewrite
COPY php.ini /usr/local/etc/php/php.ini
COPY mpm.conf /etc/apache2/mods-available/mpm_prefork.conf
COPY decode.php /var/www/html/decode.php
COPY index.php /var/www/html/index.php
COPY sess.php /var/www/html/sess.php
EXPOSE 80