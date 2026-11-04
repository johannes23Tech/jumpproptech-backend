FROM richarvey/nginx-php-fpm:latest

WORKDIR /var/www/html

# Copy everything from your repo into the container
COPY . .

# Ensure the certificate has the correct read permissions
RUN chmod 644 DigiCertGlobalRootG2.crt.pem

# Install PHP dependencies
RUN composer install --no-interaction --no-scripts --no-suggest

EXPOSE 80