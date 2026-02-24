FROM ubuntu:14.04
ENV DEBIAN_FRONTEND noninteractive

RUN \
    echo 'APT::Get::Assume-Yes "true";' > /etc/apt/apt.conf.d/90forceyes;\
    echo 'deb http://archive.ubuntu.com/ubuntu trusty main universe restricted' > /etc/apt/sources.list;\
    echo 'deb http://archive.ubuntu.com/ubuntu trusty-updates  main universe restricted' >> /etc/apt/sources.list;\
    apt-get update;\
    echo exit 101 > /usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d;\
    dpkg-divert --local --rename --add /sbin/initctl;\
    ln -sf /bin/true /sbin/initctl;\
    apt-get -y upgrade && apt-get clean ;\
    apt-get install gcc-multilib wget

RUN \
    cd /tmp ;\
    wget --no-check-certificate --no-cookies --header "Cookie: oraclelicense=accept-securebackup-cookie" -O jdk-1_5_0_05-linux-amd64.bin http://download.oracle.com/otn-pub/java/jdk/1.5.0_05/jdk-1_5_0_05-linux-amd64.bin

# alternate  java method disabled: download local jdk
#ADD jdk-1_5_0_5-linux-amd64.bin /tmp/

RUN \
    echo yes|sh /tmp/jdk-1_5_0_05-linux-amd64.bin ;\
    rm /tmp/jdk-1_5_0_05-linux-amd64.bin

ENV JAVA_HOME /jdk1.5.0_05
ENV PATH /jdk1.5.0_05/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin