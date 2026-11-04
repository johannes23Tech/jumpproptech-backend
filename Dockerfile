FROM richarvey/nginx-php-fpm:latest

WORKDIR /var/www/html

# Copy everything
COPY . .

# Ensure the cert is in the exact working directory and readable by the server user
RUN cp DigiCertGlobalRootG2.crt.pem /var/www/html/DigiCertGlobalRootG2.crt.pem
RUN chmod 644 /var/www/html/DigiCertGlobalRootG2.crt.pem

# Install dependencies
RUN composer install --no-interaction --no-scripts --no-suggest

EXPOSE 80