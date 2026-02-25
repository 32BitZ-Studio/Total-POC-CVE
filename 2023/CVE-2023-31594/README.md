# CVE-2023-31594
IC Realtime ICIP-P2012T is vulnerable to Incorrect Access Control

Unauthenticated Streaming Channel in IC Realtime IP PTZ Dome Camera ICIP-P2012 software version:  2.420

The live feed (MJPEG) can be streamed via an exposed HTTP channel using VLC network stream. This vulnerability critically affects confidentiality of customers and could be used in reconnaissance phase (identify people, assets, passwords etc.).

# Proof of Concept (POC)

If HTTP streaming is allowed, a URL path could be used to allow user to
MJPEG stream camera without any required authentication.

The path:
``` http://ip:port/cgi-bin/mjpg/video.cgi?[channel=1]&subtype=1```

![image](https://github.com/Yozarseef95/CVE-2023-31594/assets/128100303/7ef322ff-9861-4cdc-8972-9e99b2bb0de8)

[Discoverer]
> Youssef Mohamed - Cloud Consultancy for Digitalization & Security
