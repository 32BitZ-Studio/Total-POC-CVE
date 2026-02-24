FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc-dev \
    && rm -rf /var/lib/apt/lists/*

COPY gateway_backdoor.c /src/
RUN gcc -Wall -Wextra -O2 -o /usr/local/bin/gateway_backdoor /src/gateway_backdoor.c -lpthread

EXPOSE 504

ENTRYPOINT ["/usr/local/bin/gateway_backdoor"]
CMD ["504", "192.168.95.2", "502"]
