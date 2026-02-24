In order to build and run images give this command inside a software folder

```sh
sh build.sh
```

### CVE-2008-2938 Tomcat path traversal
Present in ./Tomcat6.0.1 and ./Tomcat6.0.16
Server listen on localhost:7070

### CVE-2014-3625 Spring path traversal
Present in ./Spring4.0.1 and ./Spring4.1.1
Server listen on localhost:8080

### CVE-2014-2064 Jenkins information disclosure
Present in ./Jenkins1.503 and ./Jenkins1.531
Server listen on localhost:9090

### CVE-2016-1240 Tomcat privilege escalation
Present in ./Tomcat6.0.39, ./Tomcat7.0.68, ./Spring4.0.1 and ./Spring4.1.1
Server listen on localhost:8080
