# reproduce environment for fuzzing lab
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# install basic tools and dependencies
RUN apt-get update && \
  apt-get install -y \
  build-essential \
  bison \
  git \
  curl \
  libevent-dev \
  ncurses-dev \
  automake \
  autoconf \
  pkg-config && \
  rm -rf /var/lib/apt/lists/*

# get tmux locally
WORKDIR /opt/tmux_cve_2020_27347/tmux
RUN git clone https://github.com/tmux/tmux.git .

# copy test scripts
COPY test_vulnerable.sh .
COPY test_fixed.sh .
COPY run_tmux_cve_test.sh .
RUN chmod +x test_vulnerable.sh test_fixed.sh run_tmux_cve_test.sh

# set default command
CMD ["/bin/bash"]
