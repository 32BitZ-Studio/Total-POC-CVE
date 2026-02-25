FROM debian:bookworm

# Avoid interactive prompts during apt installs
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /slipper

# Install system dependencies
RUN apt update && \
    apt install -y \
        git \
        python3 \
        python3-venv \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Create and activate virtual environment
RUN python3 -m venv /opt/venv

# Ensure venv is used by default
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip inside venv and install Python deps
# py7zr has been retrp-patched, vulns in 0.17.0 exist and work
RUN pip install --upgrade pip && \
    pip install \
        py7zr==0.17.0 \   
        legacy-cgi

# Clone the vulnerable lab
RUN git clone https://github.com/0xless/CVE-2022-44900-demo-lab.git .

EXPOSE 9999

CMD ["python", "slipper.py"]
