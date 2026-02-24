#!/bin/bash
docker stop spring401in
docker rm spring401in
docker rmi spring401
docker build -t spring401 .
docker run --net=host --name spring401in -v ./shared:/tmp/tomcat7/shared -i -t spring401
