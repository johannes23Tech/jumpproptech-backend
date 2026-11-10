FROM richarvey/nginx-php-fpm:latest

WORKDIR /var/www/html

# Copy everything from your repo into the container
COPY . .

# PHP runtime hardening (display_errors off, expose_php off, upload limits).
COPY deploy/php-hardening.ini /usr/local/etc/php/conf.d/99-security.ini

# nginx security snippet. Include it from the server block:
#   include /etc/nginx/snippets/jumpproptech-security.conf;
COPY deploy/nginx-security.conf /etc/nginx/snippets/jumpproptech-security.conf

# Ensure the certificate has the correct read permissions
RUN chmod 644 DigiCertGlobalRootG2.crt.pem

# Install PHP dependencies
RUN composer install --no-interaction --no-scripts --no-suggest

EXPOSE 80
