FROM tomcat:9.0.111-jre25-temurin-noble
RUN mkdir -p "$CATALINA_HOME/uploads"
WORKDIR $CATALINA_HOME/webapps
ADD struts-app/target/upload-1.0.0.war ROOT.war
EXPOSE 8080
CMD ["catalina.sh", "run"]
