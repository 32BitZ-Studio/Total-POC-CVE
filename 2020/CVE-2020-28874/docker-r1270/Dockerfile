FROM php:7.2-apache
RUN apt update
RUN apt install -y libzip-dev zip libpng-dev && docker-php-ext-configure zip --with-libzip && docker-php-ext-install zip
RUN docker-php-ext-install pdo pdo_mysql gd
RUN usermod -u 1000 www-data
RUN usermod -G staff www-data
COPY php.ini "$PHP_INI_DIR/"


