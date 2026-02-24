# Vulnerable Struts2 application

## Requirements

1. Maven (https://maven.apache.org)
1. Struts <= 2.5.10

## CVE-2017-5638 - Apache Struts 2 Multipart form RCE

### Requirements

1. Locate a URL that issues a multipart form POST

### Getting Started

1. The application / server can be started with the following maven command: `mvn jetty:run`.
1. Run the exploit (https://www.exploit-db.com/exploits/41570/) against the following URL http://localhost:8080/fileupload

## CVE: 2017-98505 - Apache Struts 2 REST Plugin RCE

### Requirements

1. Struts REST Plugin
1. Struts Convention Plugin
1. A Create item REST URL exists and can be POSTed to. For example: `http://localhost:8080/pizza/1`. It is important to follow the struts2 plugin naming convention to get everything wired up automatically.

### Getting Started

1. The application / server can be started with the following maven command: `mvn jetty:run`.
1. The `payload.xml` file contains the XML payload to POST to the vulnerable app / REST interface.
1. Line 17 of the `payload.txt` file can be updated to run any command. It is currently set to spawn calc.exe (Windows). Replace with `/bin/sh` for Linux etc.

An attacker can POST the payload to gain RCE:

``` bash
curl -v -H "Content-Type:application/xml" -X POST -d @payload.txt http://localhost:8080/shapes/1
```
