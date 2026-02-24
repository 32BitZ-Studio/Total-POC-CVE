FROM ubuntu:18.04

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y maven 
RUN apt search openjdk-\(\.\)\+-jre$
RUN apt search openjdk-\(\.\)\+-jdk$
RUN apt-get install -y openjdk-8-jdk
RUN apt-get install -y openjdk-8-jre

ADD ./volume /
RUN mvn install
RUN mvn exec:java
#mvn install
#mvn dependency:copy-dependencies
#RUN (cd /volume && mvn exec:java)
