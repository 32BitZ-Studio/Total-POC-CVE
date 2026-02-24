#!/bin/bash
docker stop tomcat601in
docker rm tomcat601in
docker rmi tomcat601
docker build -t tomcat601 .
# -p parameter is useless
docker run --net=host --name tomcat601in -i -t tomcat601
