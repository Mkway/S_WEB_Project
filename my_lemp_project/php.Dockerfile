FROM php:8.2-fpm-alpine
RUN docker-php-ext-install pdo_mysql \
    && mkdir -p /var/www/html/uploads \
    && chown -R www-data:www-data /var/www/html/uploads