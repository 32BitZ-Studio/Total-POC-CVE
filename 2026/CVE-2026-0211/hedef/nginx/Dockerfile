FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    cmake \
    git \
    wget \
    libpcre3-dev \
    zlib1g-dev \
    libssl-dev \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN wget https://nginx.org/download/nginx-1.25.3.tar.gz && \
    tar zxf nginx-1.25.3.tar.gz

WORKDIR /src/nginx-1.25.3

# Savunma yamasını kopyalayıp entegre ediyoruz
COPY savunma/CVE-2026-0211-defense.patch /src/nginx-1.25.3/
RUN patch -p0 < CVE-2026-0211-defense.patch

# Compile with ASAN/UBSAN and HTTP/3
RUN ./configure \
    --with-http_v3_module \
    --with-cc="clang" \
    --with-cc-opt="-fsanitize=address,undefined -g -O0 -fno-omit-frame-pointer" \
    --with-ld-opt="-fsanitize=address,undefined" \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid && \
    make -j$(nproc) && \
    make install

RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/key.pem -out /etc/nginx/cert.pem \
    -subj "/C=US/ST=State/L=City/O=Lab/OU=SecOps/CN=localhost"

# Config dosyasını yeni klasör yolundan alıyoruz
COPY hedef/nginx/nginx.conf /etc/nginx/nginx.conf
COPY hedef/website /etc/nginx/html/website

ENV ASAN_OPTIONS="detect_leaks=0,halt_on_error=0,log_path=/var/log/nginx/asan"

CMD ["nginx", "-g", "daemon off;"]
