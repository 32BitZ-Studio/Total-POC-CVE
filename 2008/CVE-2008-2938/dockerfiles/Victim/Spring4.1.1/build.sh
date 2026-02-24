#!/bin/bash
docker stop spring411in
docker rm spring411in
docker build -t spring411 .
docker run --net=host --name spring411in -v ./shared:/tmp/tomcat7/shared -i -t spring411
