FROM cved/base-lamp

LABEL author="cved (cved@protonmail.com)"
LABEL maintainer="cved (cved@protonmail.com)"

ENV LANG C.UTF-8
ENV LANGUAGE C.UTF-8
ENV LC_ALL C.UTF-8

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update \
    && apt-get -y install \
    php7.0-curl \
    php-mcrypt \
    && apt-get autoremove \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/tmp/*

COPY build/joomla/joomla-3.6.4.zip /tmp/
COPY build/joomla/configuration.php /tmp/
COPY build/joomla/db.sql /

RUN rm -rf /var/www/html/* \
    && unzip -x /tmp/joomla-3.6.4.zip -d /var/www/html/ \
    && rm -rf /var/www/html/installation/ \
    && mv -f /tmp/configuration.php /var/www/html/ \
    && mv -f /var/www/html/robots.txt.dist /var/www/html/robots.txt \
    && chown -R www-data:www-data /var/www/html/ \
    && rm -f /tmp/*

COPY build/main.sh /

EXPOSE 80

CMD ["/main.sh"]
