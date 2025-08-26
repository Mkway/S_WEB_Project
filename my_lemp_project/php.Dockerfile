# Stage 1: Builder
FROM php:8.2-fpm-alpine AS builder

WORKDIR /var/www/html

# Copy composer files first to leverage caching
COPY src/composer.json composer.json
COPY src/composer.lock composer.lock

RUN docker-php-ext-install pdo_mysql \
    && apk add --no-cache git \
    && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer \
    && composer install --no-dev --optimize-autoloader # Install production dependencies

# Stage 2: Production
FROM php:8.2-fpm-alpine

# Copy only necessary extensions and application files
# Assuming pdo_mysql is the only extension
RUN docker-php-ext-install pdo_mysql

# Create uploads directory and set permissions
RUN mkdir -p /var/www/html/uploads \
    && chown -R www-data:www-data /var/www/html/uploads

# Copy Composer vendor directory from builder stage
COPY --from=builder /var/www/html/vendor /var/www/html/vendor

# Copy application source code
COPY src /var/www/html

WORKDIR /var/www/html
