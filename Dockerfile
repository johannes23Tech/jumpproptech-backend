FROM richarvey/nginx-php-fpm:latest
WORKDIR /var/www/html
COPY . .
RUN composer install --no-interaction --no-scripts --no-suggest
EXPOSE 80