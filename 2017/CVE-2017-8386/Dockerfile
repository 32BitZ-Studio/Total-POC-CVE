FROM ubuntu:16.04

ENV DEBIAN_FRONTEND=noninteractive

# 필요한 패키지 설치
RUN apt-get update && apt-get install -y \
    wget \
    build-essential \
    zlib1g-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    libexpat1-dev \
    gettext \
    openssh-server \
    sudo \
    vim

# git 2.12.2 다운로드 및 설치
RUN cd /tmp && \
    wget https://github.com/git/git/archive/v2.12.2.tar.gz && \
    tar -zxvf v2.12.2.tar.gz && \
    cd git-2.12.2 && \
    make prefix=/usr/local all && \
    make prefix=/usr/local install

# SSH 세팅
RUN mkdir /var/run/sshd

# git 사용자 추가 및 git-shell 설정
RUN useradd -m -d /home/git -s /usr/bin/git-shell git && \
    echo "git:gitpass" | chpasswd

# SSH 키 디렉토리 설정
RUN mkdir /home/git/.ssh && \
    chmod 700 /home/git/.ssh && \
    chown git:git /home/git/.ssh

# git-shell 전용 명령 디렉토리
RUN mkdir /home/git/git-shell-commands && \
    touch /home/git/git-shell-commands/no-interactive-login && \
    echo "echo 'Interactive shell access is not allowed.'" > /home/git/git-shell-commands/no-interactive-login && \
    chmod +x /home/git/git-shell-commands/no-interactive-login && \
    chown -R git:git /home/git/git-shell-commands

# SSH 서버 설정 수정
RUN sed -i 's@#AuthorizedKeysFile.*@AuthorizedKeysFile .ssh/authorized_keys@' /etc/ssh/sshd_config && \
    sed -i 's@#Port 22@Port 22@' /etc/ssh/sshd_config && \
    sed -i 's@#PermitRootLogin prohibit-password@PermitRootLogin no@' /etc/ssh/sshd_config && \
    sed -i 's@#PasswordAuthentication yes@PasswordAuthentication yes@' /etc/ssh/sshd_config && \
    echo "StrictModes no" >> /etc/ssh/sshd_config

# 포트 오픈
EXPOSE 22

# SSH 실행
CMD ["/usr/sbin/sshd", "-D"]
