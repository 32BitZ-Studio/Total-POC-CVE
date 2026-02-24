#!/bin/bash
docker stop jenkins1531in
docker rm jenkins1531in
docker build -t jenkins1531 .
docker run --net=host --name jenkins1531in -v ./shared:/tmp/tomcat7/shared -i -t jenkins1531
