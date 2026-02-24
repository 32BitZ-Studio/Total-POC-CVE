FROM cved/base-lamp

LABEL author="cved (cved@protonmail.com)"
LABEL maintainer="cved (cved@protonmail.com)"

ENV LANG C.UTF-8
ENV LANGUAGE C.UTF-8
ENV LC_ALL C.UTF-8

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update \
    && apt-get -y install \
    exiftran \
    && apt-get autoremove \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY build/elFinder-2.1.47.tar.gz /tmp/

RUN rm -rf /var/www/html/* \
    && tar -xzf /tmp/elFinder-2.1.47.tar.gz -C /var/www/html \
    && mv /var/www/html/elFinder-2.1.47/php/connector.minimal.php-dist /var/www/html/elFinder-2.1.47/php/connector.minimal.php \
    && chown -R www-data:www-data /var/www/html/ \
    && rm -f /tmp/*

COPY build/main.sh /

EXPOSE 80

CMD ["/main.sh"]
