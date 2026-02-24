FROM cved/base-joomla

LABEL author="cved (cved@protonmail.com)"
LABEL maintainer="cved (cved@protonmail.com)"

ENV LANG C.UTF-8
ENV LANGUAGE C.UTF-8
ENV LC_ALL C.UTF-8

COPY build/com_j2store_v3-3.3.6-core.zip /tmp/
COPY build/main.sh /

EXPOSE 80

CMD ["/main.sh"]
