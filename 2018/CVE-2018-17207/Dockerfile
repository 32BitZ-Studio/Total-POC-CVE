FROM cved/base-wordpress

LABEL author="cved (cved@protonmail.com)"
LABEL maintainer="cved (cved@protonmail.com)"

ENV LANG C.UTF-8
ENV LANGUAGE C.UTF-8
ENV LC_ALL C.UTF-8

COPY build/duplicator.1.2.40.zip /tmp/
COPY build/backup/installer.php /var/www/html/
COPY build/backup/20190129_cved_7db52744291373ed2504190129202234_archive.zip /var/www/html/
COPY build/backup/backup.sh /

RUN unzip -x /tmp/duplicator.1.2.40.zip -d /var/www/html/wp-content/plugins/ \
    && chown -R www-data:www-data /var/www/html/ \
    && rm /tmp/*

COPY build/main.sh /

EXPOSE 80

CMD ["/main.sh"]
