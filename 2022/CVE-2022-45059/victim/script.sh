#!/bin/sh

curl -s -S -m 1 \
  -H "Host: localhost" \
  -H "cookie: flag=supersecretcookie;" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
  -H "Cache-Control: no-cache" \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -H "Accept-Language: nb-NO,nb;q=0.9" \
  http://frontend > /dev/null