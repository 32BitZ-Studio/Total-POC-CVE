FROM php:5.6.38-apache

RUN apt-get update \
    && apt-get install -y libc-client-dev libkrb5-dev ssh-client \
    && docker-php-ext-configure imap --with-kerberos --with-imap-ssl \
    && docker-php-ext-install imap 

EXPOSE 80
