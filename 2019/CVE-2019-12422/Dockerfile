FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG en_US.UTF-8

RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://mirrors.bfsu.edu.cn/ubuntu|g' /etc/apt/sources.list && \
    sed -i '/security.ubuntu.com/d' /etc/apt/sources.list

# 安装依赖组件
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    tar \
    wget \
    curl \
    unzip \
    netcat \
    mysql-client \
    
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# 安装jdk和maven
COPY jdk-8u65-linux-x64.tar.gz /opt/
COPY apache-maven-3.1.1-bin.tar.gz /opt/

RUN tar -xzf jdk-8u65-linux-x64.tar.gz && \
    tar -xzf apache-maven-3.1.1-bin.tar.gz && \
    rm jdk-8u65-linux-x64.tar.gz apache-maven-3.1.1-bin.tar.gz

RUN mv jdk1.8.0_65 java && \
    mv apache-maven-3.1.1 maven

ENV JAVA_HOME=/opt/java
ENV MAVEN_HOME=/opt/maven
ENV PATH=$JAVA_HOME/bin:$MAVEN_HOME/bin:$PATH

RUN java -version && mvn -version

# 源码准备
WORKDIR /workspace
COPY RuoYi-4.2 /workspace/RuoYi-4.2
COPY run.sh /workspace/
RUN chmod +x /workspace/run.sh

# 初次打包，建立缓存以提升后续运行速度
RUN cd RuoYi-4.2 && mvn install


CMD ["/bin/bash", "/workspace/run.sh"]
