# =============================================================================
# FrostyGoop District Heating Simulation
# Vulnerable Modbus TCP Controller (CVE-2019-14462)
# =============================================================================

FROM debian:11 AS base

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libpthread-stubs0-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# -----------------------------------------------------------------------------
# Build UNPATCHED vulnerable libmodbus 3.1.2 from local copy
#
# IMPORTANT: This is the original vulnerable version with CVE-2019-14462
# The official GitHub release v3.1.2 has been patched and will NOT demonstrate
# the vulnerability. We use a local unpatched copy for this security demonstration.
#
# DO NOT upgrade - vulnerability is intentional for demonstration
# -----------------------------------------------------------------------------
COPY libmodbus_3.1.2 /src/libmodbus-3.1.2

RUN cd libmodbus-3.1.2 \
    && ./autogen.sh \
    && ./configure --prefix=/usr/local \
    && make \
    && make install \
    && ldconfig

# Copy all source files
COPY Makefile /src/
COPY *.c /src/
COPY *.h /src/

# =============================================================================
# Normal build - for crash demonstration
# =============================================================================
FROM base AS normal

# Install debugging tools
RUN apt-get update && apt-get install -y tcpdump iproute2 && rm -rf /var/lib/apt/lists/*

RUN make clean && make release

COPY start-plc.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/start-plc.sh

EXPOSE 502

ENV TERM=xterm-256color

CMD ["/usr/local/bin/start-plc.sh"]

# =============================================================================
# ASAN build - for CVE-2022-0367 proof (detects heap overflow)
# Uses newer libmodbus with start_address feature but BEFORE the fix
# =============================================================================
FROM debian:11 AS asan

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libpthread-stubs0-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Build libmodbus WITH ASAN instrumentation
# Using commit ebc4f478 which has start_address feature but is vulnerable to CVE-2022-0367
COPY libmodbus_vulnerable_0367 /src/libmodbus

RUN cd libmodbus \
    && ./autogen.sh \
    && ./configure --prefix=/usr/local CFLAGS="-fsanitize=address -g -O1" LDFLAGS="-fsanitize=address" \
    && make \
    && make install \
    && ldconfig

# Install debugging tools
RUN apt-get update && apt-get install -y tcpdump iproute2 && rm -rf /var/lib/apt/lists/*

# Copy all source files
COPY Makefile /src/
COPY *.c /src/
COPY *.h /src/

RUN make clean && make asan

COPY start-plc.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/start-plc.sh

# ASAN options
ENV ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:print_legend=0:color=always
ENV TERM=xterm-256color

EXPOSE 502

CMD ["/usr/local/bin/start-plc.sh"]

# =============================================================================
# CVE-2022-0367 build - WITHOUT ASAN (for crash/corruption demonstration)
# Uses newer libmodbus with start_address feature but BEFORE the fix
# =============================================================================
FROM debian:11 AS cve0367

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libpthread-stubs0-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Build libmodbus WITHOUT ASAN (normal build)
# Using commit ebc4f478 which has start_address feature but is vulnerable to CVE-2022-0367
COPY libmodbus_vulnerable_0367 /src/libmodbus

RUN cd libmodbus \
    && ./autogen.sh \
    && ./configure --prefix=/usr/local \
    && make \
    && make install \
    && ldconfig

# Install debugging tools
RUN apt-get update && apt-get install -y tcpdump iproute2 && rm -rf /var/lib/apt/lists/*

# Copy all source files
COPY Makefile /src/
COPY *.c /src/
COPY *.h /src/

RUN make clean && make cve0367

COPY start-plc.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/start-plc.sh

ENV TERM=xterm-256color

EXPOSE 502

CMD ["/usr/local/bin/start-plc.sh"]
