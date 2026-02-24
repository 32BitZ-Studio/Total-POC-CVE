#!/bin/bash
docker stop tomcat6016in
docker rm tomcat6016in
docker build -t tomcat6016 .
# -p parameter is useless
docker run --net=host --name tomcat6016in -i -t tomcat6016
