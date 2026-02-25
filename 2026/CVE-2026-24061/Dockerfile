FROM debian:11-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      inetutils-telnetd=2:2.0-1+deb11u2 \
      telnet && \
    rm -rf /var/lib/apt/lists/*

RUN useradd user1 && \
    sed -i 's/#<off># telnet/telnet/' /etc/inetd.conf

COPY docker-entrypoint.sh /docker-entrypoint.sh

CMD ["/docker-entrypoint.sh"]
