# Stage 1: Builder
FROM php:8.2-fpm-alpine AS builder

WORKDIR /var/www/html

# Copy composer files first to leverage caching
COPY src/composer.json composer.json
# COPY src/composer.lock composer.lock

RUN apk add --no-cache git postgresql-dev openssl-dev libpq $PHPIZE_DEPS \
    && docker-php-ext-install pdo_mysql pdo_pgsql \
    && pecl install mongodb redis \
    && docker-php-ext-enable mongodb redis

# Install Composer separately
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Create vendor directory and set permissions
RUN mkdir -p vendor && chown -R www-data:www-data vendor

# Install composer dependencies without dev dependencies and without scripts
RUN composer install --no-dev --optimize-autoloader --no-scripts || true

# Stage 2: Production
FROM php:8.2-fpm-alpine

# Copy only necessary extensions and application files
# Install MySQL, PostgreSQL and MongoDB extensions
RUN apk add --no-cache postgresql-dev openssl-dev libpq $PHPIZE_DEPS \
    && docker-php-ext-install pdo_mysql pdo_pgsql \
    && pecl install mongodb redis \
    && docker-php-ext-enable mongodb redis

# Create uploads directory and set permissions
RUN mkdir -p /var/www/html/uploads \
    && chown -R www-data:www-data /var/www/html/uploads

# Copy Composer vendor directory from builder stage
COPY --from=builder /var/www/html/vendor /var/www/html/vendor

# Copy application source code
COPY src /var/www/html

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["php-fpm"]

WORKDIR /var/www/html
