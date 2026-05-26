FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    tcpdump \
    tshark \
    iproute2 \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /monitor
CMD ["/bin/bash"]
