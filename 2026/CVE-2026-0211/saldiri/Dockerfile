FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    python3 \
    python3-pip \
    python3-venv \
    git \
    wget \
    netcat-traditional \
    nmap \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Setup python environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install scapy

WORKDIR /fuzzer
CMD ["/bin/bash"]
