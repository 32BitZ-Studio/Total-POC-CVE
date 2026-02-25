# Use offical ubuntu image with a fix version
FROM ubuntu:jammy-20230624

# Set timezone environment variable
ENV TZ=Europe/Paris

# Set geographic area using above variable
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Remove annoying messages during package installation
ARG DEBIAN_FRONTEND=noninteractive

# Install packages: web server Apache, PHP and extensions
RUN apt-get update && apt-get install --no-install-recommends -y \
  apache2 \
  apache2-utils \
  ca-certificates \
  git \
  php \
  libapache2-mod-php \
  php-curl \
  php-dom \
  php-gd \
  php-intl \
  php-json \
  php-mbstring \
  php-xml \
  php-zip && \
  apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy virtual host configuration from current path onto existing 000-default.conf
COPY default.conf /etc/apache2/sites-available/000-default.conf

# Remove default content (existing index.html)
RUN rm /var/www/html/*

# Clone the Kirby Starterkit using the latest vulnerable version
RUN git clone --depth 1 --branch 3.9.5 https://github.com/getkirby/starterkit.git /var/www/html

# Deploy the RSS feed example for proof of concept
# https://getkirby.com/docs/guide/virtual-pages/content-from-rss-feed
RUN mkdir /var/www/html/content/rssfeed
COPY rssfeed.txt /var/www/html/content/rssfeed/rssfeed.txt
# this one has a minor modification to accept an RSS feed URL from user input
COPY rssfeed-model.php /var/www/html/site/models/rssfeed.php
COPY rssfeed-template.php /var/www/html/site/templates/rssfeed.php
COPY feeditem-template.php /var/www/html/site/templates/feeditem.php

# Fix files and directories ownership
RUN chown -R www-data:www-data /var/www/html/

# Activate Apache modules headers & rewrite
RUN a2enmod headers rewrite

# Tell container to listen to port 80 at runtime
EXPOSE 80

# Start Apache web server
CMD [ "/usr/sbin/apache2ctl", "-DFOREGROUND" ]