# CVE-2022-45059-demo

Varnish Cache releases 7.0.0, 7.0.1, 7.0.2, 7.0.3, 7.1.0, 7.1.1 and 7.2.0 have a request smuggling vulnerability where an attacker can request that the content-length header is made hop-by-hop.
This is a demo consisting of a Spring Boot web application running behind a vulnerable version of Varnish Cache.
A "victim" sends requests to the application every 5 seconds and the goal is to steal his cookies.

## Running the application

### Option 1 - Using prebuilt images
```
docker compose up
```
View the website at: http://localhost

### Option 2 - Build the images yourself
```
docker build -t <TAG_NAME> frontend
docker build -t <TAG_NAME> backend
docker build -t <TAG_NAME> victim
```
Update `docker-compose.yml` with your images and run `docker compose up`.  
View the website at: http://localhost

## Packet capture

Packet capturing is enabled on the backend and the pcap file is written to `./capture/backend.pcap`
