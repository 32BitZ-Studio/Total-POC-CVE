FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    qemu-system-arm \
    qemu-system-x86 \
    bridge-utils \
    iproute2 \
    net-tools \
    iputils-ping \
    procps \
    iptables \
    tcpdump \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Copy both seL4 images (ARM and x86)
COPY sel4-image/capdl-loader-image-arm-qemu-arm-virt /sel4-image/
COPY sel4-image/capdl-loader-image-x86_64-pc99 /sel4-image/

COPY setup-network.sh /usr/local/bin/
COPY start-gateway.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh

# Default to ARM for backward compatibility
ENV GATEWAY_ARCH=arm

EXPOSE 502

CMD ["/usr/local/bin/start-gateway.sh"]
