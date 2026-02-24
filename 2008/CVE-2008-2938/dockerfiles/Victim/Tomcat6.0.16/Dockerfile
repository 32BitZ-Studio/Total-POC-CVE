FROM java5

ENV CATALINA_HOME /usr/local/tomcat
ENV PATH $CATALINA_HOME/bin:$PATH
ENV TOMCAT_TGZ_URL https://archive.apache.org/dist/tomcat/tomcat-6/v6.0.16/bin/apache-tomcat-6.0.16.tar.gz
RUN mkdir -p "$CATALINA_HOME"
WORKDIR $CATALINA_HOME

# runtime dependency for Tomcat Native Libraries
RUN apt-get update && apt-get install -y libapr1 && rm -rf /var/lib/apt/lists/*

RUN groupadd tomcat \
	&& useradd -ms /bin/bash -g tomcat -d "$CATALINA_HOME" tomcatUser \
	&& chown -R tomcatUser:tomcat "$CATALINA_HOME"

USER tomcatUser

RUN set -x \
	\
	&& wget -O tomcat.tar.gz "$TOMCAT_TGZ_URL" \
	&& tar xvf tomcat.tar.gz -C "$CATALINA_HOME" --strip-components=1

COPY ./server.xml /usr/local/tomcat/conf/server.xml
COPY ./context.xml /usr/local/tomcat/conf/context.xml
COPY ./tomcat-users.xml /usr/local/tomcat/conf/tomcat-users.xml

RUN echo "#!/bin/bash" > bin/init.sh \
	&& echo "sh /usr/local/tomcat/bin/catalina.sh start && sleep 2 && tail -f /usr/local/tomcat/logs/catalina.out" >> bin/init.sh

RUN chmod +x /usr/local/tomcat/bin/init.sh

USER root

RUN echo "10.0.75.2 moby localhost" > /etc/hosts  
RUN echo "127.0.0.1       localhost" > /etc/hosts  

USER tomcatUser

EXPOSE 7070

CMD ["bin/init.sh"]
