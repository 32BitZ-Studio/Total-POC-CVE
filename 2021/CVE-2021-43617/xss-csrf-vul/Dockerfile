FROM php:7.3-cli

#ARG user
#ARG uid

RUN apt-get update -y && apt-get install -y libmcrypt-dev

#RUN apt-get clean && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-install pdo mbstring

#COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

#RUN useradd -G www-data,root -u $uid -d /home/$user $user
#RUN mkdir -p /home/$user/.composer && chown -R $user:$user /home/$user

WORKDIR /app
#WORKDIR /var/www
COPY . /app

RUN composer install --ignore-platform-reqs

EXPOSE 8000
CMD php artisan serve --host=0.0.0.0 --port=8000