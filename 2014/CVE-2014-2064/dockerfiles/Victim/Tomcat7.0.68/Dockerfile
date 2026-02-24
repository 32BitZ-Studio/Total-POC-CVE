FROM ubuntu:16.04

ENV CATALINA_HOME /usr/share/tomcat7
ENV CATALINA_BASE /var/lib/tomcat7

RUN apt-get update
RUN apt-get install -y tomcat7=7.0.68-1 tomcat7-docs tomcat7-examples tomcat7-admin wget build-essential sudo nano
RUN cd /var/lib/tomcat7 \
	&& ln -s /usr/share/java lib
RUN echo "#!/bin/bash" > /bin/startupTomcat.sh \
	&& echo "/etc/init.d/tomcat7 restart; sleep 2 && tail -f /etc/passwd" >> /bin/startupTomcat.sh
RUN chmod +x /bin/startupTomcat.sh

USER tomcat7
RUN mkdir /tmp/tomcat7 && mkdir /tmp/tomcat7/shared
WORKDIR /tmp/tomcat7
# RUN wget http://legalhackers.com/exploits/tomcat-rootprivesc-deb.sh && chmod +x tomcat-rootprivesc-deb.sh

USER root

EXPOSE 8080

CMD ["/bin/startupTomcat.sh"]
