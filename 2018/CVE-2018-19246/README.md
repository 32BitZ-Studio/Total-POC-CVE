# CVE-2018-19246

## Proof of Concept

**Usage**

```shell
docker build -t lucas/cve-2018-19246:0.1.0 .
docker run --rm -it -p 80:80 lucas/cve-2018-19246:0.1.0
python2 Pocsuite-2.0.8/pocsuite.py -u 172.17.0.1 -r PoC.py
```

