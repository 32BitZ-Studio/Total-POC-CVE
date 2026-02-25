FROM alpine

COPY script.sh /

RUN chmod +x /script.sh
RUN apk add --no-cache curl

ENTRYPOINT watch -n 5 ./script.sh > /dev/null